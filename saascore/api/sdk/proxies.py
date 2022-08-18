import json
from typing import Union, Optional

import requests

from saascore.api.sdk.exceptions import UnexpectedContentType, UnsuccessfulConnectionError
from saascore.api.sdk.helpers import extract_response, sign_authorisation_token
from saascore.keystore.assets.credentials import GithubCredentials, SSHCredentials
from saascore.keystore.identity import Identity
from saascore.keystore.keystore import Keystore

db_endpoint_prefix = "/api/v1/db"
dor_endpoint_prefix = "/api/v1/dor"
rti_endpoint_prefix = "/api/v1/rti"


class EndpointProxy:
    def __init__(self, endpoint_prefix: str, remote_address: (str, int)) -> None:
        self._endpoint_prefix = endpoint_prefix
        self._remote_address = remote_address

    @property
    def remote_address(self):
        return self._remote_address

    def get(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, download_path: str = None,
            with_authorisation_by: Keystore = None) -> Optional[Union[dict, list]]:

        content = self._make_content(endpoint, 'GET', parameters=parameters, body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self._url(endpoint, parameters)
        try:
            if download_path:
                with requests.get(url, data=content, stream=True) as response:
                    header = {k: v for k, v in response.headers.items()}
                    if header['Content-Type'] == 'application/json':
                        return extract_response(response)

                    elif response.headers['Content-Type'] == 'application/octet-stream':
                        content = response.iter_content(chunk_size=8192)
                        with open(download_path, 'wb') as f:
                            for chunk in content:
                                f.write(chunk)
                        return header

                    else:
                        raise UnexpectedContentType({
                            'header': header
                        })

            else:
                response = requests.get(url, data=content)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def put(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, attachment_path: str = None,
            with_authorisation_by: Keystore = None) -> Union[dict, list]:

        content = self._make_content(endpoint, 'PUT', parameters=parameters, body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self._url(endpoint, parameters)
        try:
            if attachment_path:
                with open(attachment_path, 'rb') as f:
                    response = requests.put(url, data=content, files={'attachment': f.read()})
                    return extract_response(response)

            else:
                response = requests.put(url, data=content)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def post(self, endpoint: str, body: Union[dict, list, str] = None, parameters: dict = None,
             attachment_path: str = None, with_authorisation_by: Keystore = None) -> Union[dict, list]:

        content = self._make_content(endpoint, 'POST',
                                     parameters=parameters,
                                     body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self._url(endpoint, parameters)
        try:
            if attachment_path:
                with open(attachment_path, 'rb') as f:
                    response = requests.post(url, data=content, files={'attachment': f.read()})
                    return extract_response(response)

            else:
                response = requests.post(url, data=content)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def delete(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None,
               with_authorisation_by: Keystore = None) -> Union[dict, list]:

        content = self._make_content(endpoint, 'DELETE',
                                     parameters=parameters,
                                     body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self._url(endpoint, parameters)
        try:
            response = requests.delete(url, data=content)
            return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def _auth_url(self, endpoint: str, parameters: dict = None) -> str:
        url = f"{self._endpoint_prefix}{endpoint}"

        if parameters:
            for i in range(len(parameters)):
                url += '?' if i == 0 else '&'
                url += parameters[i][0] + '=' + parameters[i][1]

        return url

    def _url(self, endpoint: str, parameters: dict = None) -> str:
        return f"http://{self._remote_address[0]}:{self._remote_address[1]}{self._auth_url(endpoint, parameters)}"

    def _make_content(self, endpoint: str, action: str, parameters: dict = None, body: Union[dict, list] = None,
                      with_authorisation_by: Keystore = None):
        content = {}

        if body:
            content['body'] = json.dumps(body)

        if with_authorisation_by:
            url = f"{action}:{self._auth_url(endpoint, parameters)}"
            authorisation = {
                    'public_key': with_authorisation_by.signing_key.public_as_string(),
                    'signature': sign_authorisation_token(with_authorisation_by, url, body)
            }

            content['authorisation'] = json.dumps(authorisation)

        return content


class NodeDBProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int)):
        EndpointProxy.__init__(self, db_endpoint_prefix, remote_address)

    def get_node(self) -> dict:
        return self.get("/node")

    def get_network(self) -> list[dict]:
        return self.get("/network")

    def get_identities(self) -> dict[str, Identity]:
        return {
            item['iid']: Identity.deserialise(item) for item in self.get("/identity")
        }

    def get_identity(self, iid: str) -> Optional[Identity]:
        serialised_identity = self.get(f"/identity/{iid}")
        return Identity.deserialise(serialised_identity) if serialised_identity else None

    def update_identity(self, identity) -> None:
        self.post('/identity', body=identity.serialise())

    def get_provenance(self, obj_id: str) -> dict:
        return self.get(f"/provenance/{obj_id}")


class DORProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int)):
        EndpointProxy.__init__(self, dor_endpoint_prefix, remote_address)

    def search(self, patterns: list[str] = None, owner_iid: str = None,
               data_type: str = None, data_format: str = None,
               c_hashes: list[str] = None) -> dict:
        body = {}

        if patterns is not None and len(patterns) > 0:
            body['patterns'] = patterns

        if owner_iid is not None:
            body['owner_iid'] = owner_iid

        if data_type is not None:
            body['data_type'] = data_type

        if data_format is not None:
            body['data_format'] = data_format

        if c_hashes is not None:
            body['c_hashes'] = c_hashes

        return self.get('', body=body)

    def statistics(self) -> dict:
        return self.get('/statistics')

    def add_data_object(self, content_path: str, owner: Identity, access_restricted: bool, content_encrypted: bool,
                        data_type: str, data_format: str, created_by: str, recipe: dict = None) -> dict:
        body = {
            'data_type': data_type,
            'data_format': data_format,
            'created_by': created_by,
            'owner_iid': owner.id,
            'access_restricted': access_restricted,
            'content_encrypted': content_encrypted
        }

        if recipe is not None:
            body['recipe'] = recipe

        return self.post('/add', body=body, attachment_path=content_path)

    def add_gpp_data_object(self, source: str, commit_id: str, proc_path: str, proc_config: str, owner: Identity,
                            created_by: str, recipe: dict = None, github_credentials: GithubCredentials = None) -> dict:
        body = {
            'data_type': 'Git-Processor-Pointer',
            'data_format': 'json',
            'created_by': created_by,
            'owner_iid': owner.id,
            'gpp': {
                'source': source,
                'commit_id': commit_id,
                'proc_path': proc_path,
                'proc_config': proc_config
            }
        }

        if recipe is not None:
            body['recipe'] = recipe

        if github_credentials:
            body['github_credentials'] = {
                'login': github_credentials.login,
                'personal_access_token': github_credentials.personal_access_token
            }

        return self.post('/add-gpp', body=body)

    def delete_data_object(self, obj_id: str, with_authorisation_by: Keystore) -> (str, dict):
        return self.delete(f"/{obj_id}", with_authorisation_by=with_authorisation_by)

    def get_meta(self, obj_id: str) -> (str, dict):
        return self.get(f"/{obj_id}/meta")

    def get_content(self, obj_id: str, with_authorisation_by: Keystore, download_path: str) -> dict:
        return self.get(f"/{obj_id}/content", download_path=download_path, with_authorisation_by=with_authorisation_by)

    def grant_access(self, obj_id: str, authority: Keystore, identity: Identity) -> dict:
        return self.post(f"/{obj_id}/access/{identity.id}", with_authorisation_by=authority)

    def revoke_access(self, obj_id: str, authority: Keystore, identity: Identity) -> dict:
        return self.delete(f"/{obj_id}/access/{identity.id}", with_authorisation_by=authority)

    def transfer_ownership(self, obj_id: str, authority: Keystore, new_owner: Identity) -> dict:
        # TODO: reminder that the application layer is responsible to transfer the content_key to the new owner
        return self.put(f"/{obj_id}/owner/{new_owner.id}", with_authorisation_by=authority)

    def update_tags(self, obj_id: str, authority: Keystore, tags: dict) -> dict:
        body = []
        for key, value in tags.items():
            body.append({
                'key': key,
                'value': value
            })

        return self.put(f"/{obj_id}/tags", body=body, with_authorisation_by=authority)

    def remove_tags(self, obj_id: str, authority: Keystore, keys: list) -> dict:
        return self.delete(f"/{obj_id}/tags", body=keys, with_authorisation_by=authority)


class RTIProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int)) -> None:
        EndpointProxy.__init__(self, rti_endpoint_prefix, remote_address)

    def get_deployed(self):
        return self.get(f"")

    def deploy(self, proc_id: str, deployment: str = "native", gpp_custodian: str = None,
               ssh_credentials: SSHCredentials = None, github_credentials: GithubCredentials = None) -> dict:

        body = {
            'deployment': deployment,
        }

        if gpp_custodian:
            body['gpp_custodian'] = gpp_custodian

        # do we have credentials to encrypt?
        if ssh_credentials or github_credentials:
            # get info about the node (TODO: there is probably a better way to get the id of the peer)
            db = NodeDBProxy(self.remote_address)
            peer_info = db.get_node()
            peer = Identity.deserialise(peer_info['identity'])

            if ssh_credentials:
                ssh_credentials_serialised = json.dumps({
                    'host': ssh_credentials.host,
                    'login': ssh_credentials.login,
                    'key': ssh_credentials.key,
                    'key_is_password': ssh_credentials.key_is_password
                })
                body['ssh_credentials'] = peer.encrypt(ssh_credentials_serialised.encode('utf-8')).hex()

            if github_credentials:
                github_credentials_serialised = json.dumps({
                    'login': github_credentials.login,
                    'personal_access_token': github_credentials.personal_access_token
                })
                body['github_credentials'] = peer.encrypt(github_credentials_serialised.encode('utf-8')).hex()

        return self.post(f"/{proc_id}", body=body)

    def undeploy(self, proc_id: str) -> dict:
        return self.delete(f"/{proc_id}")

    def get_descriptor(self, proc_id: str) -> dict:
        return self.get(f"/{proc_id}/descriptor")

    def get_status(self, proc_id: str) -> dict:
        return self.get(f"/{proc_id}/status")

    def submit_job(self, proc_id: str, job_input: list, job_output: list, user: Identity) -> dict:
        return self.post(f"/{proc_id}/jobs", body={
            'processor_id': proc_id,
            'input': job_input,
            'output': job_output,
            'user_iid': user.id
        })

    def resume_job(self, proc_id: str, reconnect_info: dict) -> dict:
        return self.put(f"/{proc_id}/jobs", body=reconnect_info)

    def get_jobs(self, proc_id: str) -> dict:
        return self.get(f"/{proc_id}/jobs")

    def get_job_info(self, job_id: str) -> (dict, dict):
        r = self.get(f"/job/{job_id}")
        return r['job_descriptor'], r['status']

    def put_permission(self, req_id: str, permission: str) -> None:
        self.post(f"/permission/{req_id}", body=permission)
