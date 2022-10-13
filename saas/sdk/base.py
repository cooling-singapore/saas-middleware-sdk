from __future__ import annotations

import os
import time
from typing import List, Union, Dict, Optional

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import validate_json
from saas.core.identity import Identity
from saas.core.keystore import Keystore
from saas.core.logging import Logging
from saas.dor.proxy import DORProxy
from saas.dor.schemas import DataObject, CDataObject, GPPDataObject, DataObjectProvenance
from saas.nodedb.proxy import NodeDBProxy
from saas.nodedb.schemas import NodeInfo
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import Processor, Task, Job, JobStatus, ProcessorStatus

logger = Logging.get('saas.sdk.base')


class SaaS:
    class Processor:
        def __init__(self, processor: Processor, user: Keystore, node: NodeInfo) -> None:
            self._processor = processor
            self._user = user
            self._rti = RTIProxy(node.rest_address)
            self._node = node

        @property
        def name(self) -> str:
            return self._processor.gpp.proc_descriptor.name

        @property
        def descriptor(self) -> Processor:
            return self._processor

        def undeploy(self) -> None:
            self._rti.undeploy(self._processor.proc_id, self._user)

        def status(self) -> ProcessorStatus:
            return self._rti.get_status(self._processor.proc_id)

        def execute(self, consume: Dict[str, Union[SaaS.CDataObject, Dict]], product_restricted_access: bool = False,
                    product_owner: Identity = None) -> Dict[str, SaaS.CDataObject]:

            # process consumed objects
            job_input = []
            for obj_desc in self._processor.gpp.proc_descriptor.input:
                # do we have the required object by name?
                if obj_desc.name not in consume:
                    raise SaaSRuntimeException(f"No input object '{obj_desc.name}' found.")

                # is it by-reference or by-value?
                obj = consume[obj_desc.name]
                if isinstance(obj, SaaS.CDataObject):
                    meta = consume[obj_desc.name].meta

                    # create a signature (if needed)
                    signature = self._user.sign(f"{self._node.identity.id}:{meta.obj_id}".encode('utf-8')) if \
                        meta.access_restricted else None

                    job_input.append(Task.InputReference(
                        name=obj_desc.name,
                        type='reference',
                        obj_id=meta.obj_id,
                        user_signature=signature,
                        c_hash=meta.c_hash
                    ))

                else:
                    # validate the content (if there is a schema)
                    if obj_desc.data_schema and not validate_json(obj, obj_desc.data_schema):
                        raise SaaSRuntimeException(f"By-value input object '{obj_desc.name}' does not comply with"
                                                   f"schema {obj_desc.data_schema}.",
                                                   details={'instance': obj, 'schema': obj_desc.data_schema})

                    job_input.append(Task.InputValue(
                        name=obj_desc.name,
                        type='value',
                        value=obj
                    ))

            # process produced objects
            job_output = []
            for obj in self._processor.gpp.proc_descriptor.output:
                job_output.append(Task.Output(
                    name=obj.name,
                    owner_iid=product_owner.id if product_owner else self._user.identity.id,
                    restricted_access=product_restricted_access,
                    content_encrypted=False,
                    target_node_iid=self._node.identity.id
                ))

            # try to submit the job
            job: Job = self._rti.submit_job(self._processor.proc_id, job_input, job_output, self._user)

            # wait until the job has finished
            while True:
                status: JobStatus = self._rti.get_job_status(job.id, self._user)
                if status.state in [JobStatus.State.INITIALISED, JobStatus.State.RUNNING]:
                    time.sleep(1)

                elif status.state == JobStatus.State.SUCCESSFUL:
                    break

                else:
                    raise SaaSRuntimeException("Job execution failed/timed-out", details={
                        'errors': status.errors
                    })

            # collect information about the output data objects
            output = {}
            for name, meta in status.output.items():
                output[name] = SaaS.CDataObject(meta=meta, user=self._user)

            return output

    class DataObject:
        def __init__(self, meta: Union[CDataObject, GPPDataObject], user: Keystore) -> None:
            self._meta = meta
            self._user = user
            self._dor = DORProxy(meta.custodian.rest_address)

        def delete(self) -> DataObject:
            return self._dor.delete_data_object(self._meta.obj_id, self._user)

        def grant_access(self, identity: Identity) -> None:
            self._meta = self._dor.grant_access(self._meta.obj_id, self._user, identity)

        def revoke_access(self, identity: Identity) -> None:
            self._meta = self._dor.revoke_access(self._meta.obj_id, self._user, identity)

        def transfer_ownership(self, new_owner: Identity) -> None:
            self._meta = self._dor.transfer_ownership(self._meta.obj_id, self._user, new_owner)

        def update_tags(self, tags: List[DataObject.Tag]) -> None:
            self._meta = self._dor.update_tags(self._meta.obj_id, self._user, tags)

        def remove_tags(self, keys: List[str]) -> None:
            self._meta = self._dor.remove_tags(self._meta.obj_id, self._user, keys)

    class GPPDataObject(DataObject):
        def __init__(self, meta: GPPDataObject, user: Keystore) -> None:
            super().__init__(meta, user)

        @property
        def meta(self) -> GPPDataObject:
            return self._meta

        def deploy(self, node: NodeInfo, ssh_profile: str = None) -> SaaS.Processor:
            # does the node have an RTI?
            if not node.rti_service:
                raise SaaSRuntimeException("Node does not have an RTI service", details={
                    'node': node
                })

            # do we have SSH credentials for this profile (if applicable)
            ssh_credentials = None
            if ssh_profile:
                ssh_credentials = self._user.ssh_credentials.get(ssh_profile)
                if not ssh_credentials:
                    raise SaaSRuntimeException("No SSH credentials found for profile", details={
                        'profile': ssh_profile
                    })

            # do we have GitHub credentials for this repo?
            github_credentials = self._user.github_credentials.get(self.meta.gpp.source)

            # try to deploy the processor
            rti = RTIProxy(node.rest_address)
            proc = rti.deploy(self.meta.obj_id, self._user, gpp_custodian=self.meta.custodian.identity.id,
                              ssh_credentials=ssh_credentials, github_credentials=github_credentials)

            return SaaS.Processor(proc, self._user, node)

    class CDataObject(DataObject):
        def __init__(self, meta: CDataObject, user: Keystore) -> None:
            super().__init__(meta, user)

        @property
        def meta(self) -> CDataObject:
            return self._meta

        def download(self, destination: str, name: str = None) -> str:
            download_path = os.path.join(destination, f"{name if name else self._meta.obj_id}.{self._meta.data_format}")
            self._dor.get_content(self._meta.obj_id, self._user, download_path)
            return download_path

        def get_provenance(self) -> DataObjectProvenance:
            return self._dor.get_provenance(self._meta.c_hash)

    class Context:
        def __init__(self, dor_nodes: List[NodeInfo], rti_nodes: List[NodeInfo], user: Keystore):
            self._dor_nodes = {node.identity.id: node for node in dor_nodes}
            self._rti_nodes = {node.identity.id: node for node in rti_nodes}
            self._user = user

        @property
        def user(self) -> Keystore:
            return self._user

        def dor(self, preferred_iid: str = None) -> NodeInfo:
            # do we have any DOR?
            n = len(self._dor_nodes)
            if n == 0:
                raise SaaSRuntimeException("No DOR node found")

            # do we have the preferred node?
            if preferred_iid is not None and preferred_iid in self._dor_nodes:
                return self._dor_nodes[preferred_iid]

            # just use an arbitrary one
            return list(self._dor_nodes.values())[0]

        def rti(self, preferred_iid: str = None) -> NodeInfo:
            # do we have any RTI?
            n = len(self._rti_nodes)
            if n == 0:
                raise SaaSRuntimeException("No RTI node found")

            # do we have the preferred node?
            if preferred_iid is not None and preferred_iid in self._rti_nodes:
                return self._rti_nodes[preferred_iid]

            # just use an arbitrary one
            return list(self._rti_nodes.values())[0]

        def upload_content(self, content_path: str, data_type: str, data_format: str, access_restricted: bool,
                           content_encrypted: bool = False, creators: List[Identity] = None, license_by: bool = False,
                           license_sa: bool = False, license_nc: bool = False, license_nd: bool = False,
                           preferred_dor_iid: str = None) -> SaaS.CDataObject:

            # get DOR node
            dor = self.dor(preferred_iid=preferred_dor_iid)

            # upload data object to DOR
            dor = DORProxy(dor.rest_address)
            meta = dor.add_data_object(content_path, self._user.identity, access_restricted, content_encrypted,
                                       data_type, data_format, creators=creators, license_by=license_by,
                                       license_sa=license_sa, license_nc=license_nc, license_nd=license_nd)

            return SaaS.CDataObject(meta, self._user)

        def upload_gpp(self, source: str, commit_id: str, proc_path: str, proc_config: str,
                       creators: List[Identity] = None, preferred_dor_iid: str = None) -> SaaS.GPPDataObject:

            # get DOR node
            dor = self.dor(preferred_iid=preferred_dor_iid)

            # do we have GitHub credentials?
            github_credentials = self._user.github_credentials.get(source)

            # upload data object to DOR
            dor = DORProxy(dor.rest_address)
            meta = dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, self._user.identity,
                                           creators=creators, github_credentials=github_credentials)

            return SaaS.GPPDataObject(meta, self._user)

        def find_processor(self, proc_id: str) -> Optional[SaaS.Processor]:
            for node in self._rti_nodes.values():
                rti = RTIProxy(node.rest_address)
                for proc in rti.get_deployed():
                    if proc.proc_id == proc_id:
                        return SaaS.Processor(proc, self._user, node)
            return None

        def find_processors(self, pattern: str = None) -> List[SaaS.Processor]:
            result = []
            for node in self._rti_nodes.values():
                rti = RTIProxy(node.rest_address)
                for proc in rti.get_deployed():
                    if not pattern or pattern in proc.gpp.proc_descriptor.name:
                        result.append(SaaS.Processor(proc, self._user, node))
            return result

        def find_data_object(self, obj_id: str) -> Optional[Union[SaaS.CDataObject, SaaS.GPPDataObject]]:
            for node in self._dor_nodes.values():
                dor = DORProxy(node.rest_address)
                meta = dor.get_meta(obj_id)
                if meta:
                    if isinstance(meta, CDataObject):
                        return SaaS.CDataObject(meta, self._user)
                    else:
                        return SaaS.GPPDataObject(meta, self._user)

            return None

        def find_data_objects(self, patterns: list[str] = None, owner_iid: str = None, data_type: str = None,
                              data_format: str = None, c_hashes: list[str] = None) -> List[Union[SaaS.CDataObject,
                                                                                                 SaaS.GPPDataObject]]:

            result = []
            for node in self._rti_nodes.values():
                dor = DORProxy(node.rest_address)
                for meta in dor.search(patterns=patterns, owner_iid=owner_iid, data_type=data_type,
                                       data_format=data_format, c_hashes=c_hashes):

                    if isinstance(meta, CDataObject):
                        result.append(SaaS.CDataObject(meta, self._user))
                    else:
                        result.append(SaaS.GPPDataObject(meta, self._user))
            return result

        def get_processor(self, name: str) -> List[SaaS.Processor]:
            pass

    @classmethod
    def connect(cls, address: (str, int), user: Keystore) -> Context:
        # publish the identity (may not be needed but just to be sure)
        db = NodeDBProxy(address)
        db.update_identity(user.identity)

        # fetch information about the network
        dor_nodes: List[NodeInfo] = []
        rti_nodes: List[NodeInfo] = []
        for node in db.get_network():
            if node.rti_service:
                rti_nodes.append(node)

            if node.dor_service:
                dor_nodes.append(node)

        return SaaS.Context(dor_nodes, rti_nodes, user)
