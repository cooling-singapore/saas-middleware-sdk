from typing import List, Optional, Dict, Union

from pydantic import BaseModel, Field

from saas.core.schemas import GithubCredentials
from saas.nodedb.schemas import NodeInfo


GPP_DATA_TYPE = 'GitProcessorPointer'
GPP_DATA_FORMAT = 'json'


class DORStatistics(BaseModel):
    """
    Provides information about contents in the DOR.
    """
    data_types: List[str] = Field(..., title="Data Types", description="A list of all unqiue data types that can be found in the DOR.", example=['JSONObject', 'Heatmap'])
    data_formats: List[str] = Field(..., title="Data Formats", description="A list of all unqiue data formats that can be found in the DOR.", example=['json', 'tiff'])


class ProcessorDescriptor(BaseModel):
    """
    Provides meta information about a processor. It defines the input and output interface of the processor in terms of
    data objects that are being consumed (input) and produced (output).
    """
    class IODataObject(BaseModel):
        name: str = Field(..., title="Data Object Name", description="The name of the data object.", example="parameters")
        data_type: str = Field(..., title="Data Type", description="The data type that is expected or produced in case of an input or output data objects, respectively.", example="JSONObject")
        data_format: str = Field(..., title="Data Format", description="The data format that is expected or produced in case of an input or output data objects, respectively.", example="json")
        data_schema: Optional[dict] = Field(title="Data Schema", description="The scheme that can be used for validating the content of this data object. Note: this is only applicable in case the data type and format is `JSONObject` and `json`, respectively.")

    name: str = Field(..., title="Processor Name", description="The name of the processor", example="urban-climate-sim")
    input: List[IODataObject] = Field(..., title="Input Data Objects", description="A list of data objects that are consumed by the processor when executing a job.")
    output: List[IODataObject] = Field(..., title="Output Data Objects", description="A list of data objects that are produced by the processor when executing a job.")
    configurations: List[str] = Field(..., title="Configurations", description="A list of configurations supported by the processor", example=['default', 'ubuntu-20.04'])


class GitProcessorPointer(BaseModel):
    """
    Contains all the necessary information to refer to a specific version of a processor and where it can be located.
    For convenience, it also contains the descriptor of the processor that is being referenced.
    """
    source: str = Field(..., title="Source", description="The source where the code can be found. Typically, this is a URL pointing at a Github repository.", example="https://github.com/the-repo")
    commit_id: str = Field(..., title="Commit Id", description="The commit id to be used. This allows to refer to a specific version of the code.", example="833e8f7")
    proc_path: str = Field(..., title="", description="The relative path in the repository where the processor can be found.", example="/processor/proc_simulator")
    proc_config: str = Field(..., title="", description="The configuration that should be used.", example="default")
    proc_descriptor: ProcessorDescriptor = Field(..., title="Processor Descriptor", description="The processor descriptor is stored in the repository at the location indicated with `proc_path`. For convenience this descriptor is included in the GPP.")


class CObjectNode(BaseModel):
    """
    A content data object node is used as part of a provenance graph and/or recipes. It provides meta information
    about a specific instance of data object consumed or produced by a processor as input or output data object,
    respectively. In case of a 'by-value' data object, the actual content of the data object is included as well.
    """
    c_hash: str = Field(..., title="Content Hash", description="The content hash used to uniquely identify a specific content.", example="9ab2253fc38981f5be9c25cf0a34b62cdf334652344bdef16b3d5dbc0b74f2f1")
    data_type: str = Field(..., title="Data Type", description="The data type of the data object.", example="JSONObject")
    data_format: str = Field(..., title="Data Type", description="The data format of the data object.", example="json")
    content: Optional[dict] = Field(title="Content", description="The content of the data object (only used in case of 'by-value' data objects).", example="")


class DataObjectRecipe(BaseModel):
    """
    Provides the necessary information to reproduce a data object. Processors consume a number of input data objects
    and produce a number of data objects. In principle, given the exact same input data objects and the exact same
    processor, it should be possible to reproduce the exact same output data objects. This assumes that the processor
    itself is deterministic. A recipe contains all the necessary information in order to reproduce data objects.
    Recipes are automatically generated by the RTI. In general, recipes are not available for data objects that have
    been manually added to a DOR.
    """
    processor: GitProcessorPointer = Field(..., title="Git Processor Pointer", description="A GPP used to identify and locate the specific processor and version that has been used to generate the data object.", example="urban-climate-sim")
    consumes: Dict[str, CObjectNode] = Field(..., title="Consumed Data Objects", description="A mapping 'name -> `CObjectNode`' of all input data objects that have been consumed by the processor to produce the data object.")
    product: CObjectNode = Field(..., title="Product Data Object", description="Details about the produced data object.")
    name: str = Field(..., title="Product Name", description="The name of the data object produced by the processor.", example="air-temperature-map")


class DataObjectProvenance(BaseModel):
    """
    Provenance information is similar to data object recipes. However, provenance shows the entire history - so as far
    as the node is aware of it. This includes a history of all steps necessary to produce the data object of interest.
    Due to the nature of provenance information, the result is a graph structure. Provenance information includes data
    nodes and processor nodes that are put into relation to each other via processing steps. A step uses which processor
    is used and what data objects it consumes and produces. Steps are establishing edges between data and processor
    nodes.
    """
    class Step(BaseModel):
        """
        An individual processing step in the history of a data object. Information includes a reference to the processor
        used by this step as well as references to all input and output data objects consumed and produced by the
        processor during this step. References are used here because the same processor or data object may be used
        by more than one step.
        """
        processor: str = Field(..., title="Processor Reference", description="A unique id that refers to the corresponding processor node.")
        consumes: Dict[str, str] = Field(..., title="Consumes", description="Mapping of input data object names to data object references.")
        produces: Dict[str, str] = Field(..., title="Produces", description="Mapping of output data object names to data object references.")

    data_nodes: Dict[str, CObjectNode] = Field(..., title="Data Nodes", description="A mapping of references to specific content data object information.")
    proc_nodes: Dict[str, GitProcessorPointer] = Field(..., title="Processor Nodes", description="A mapping of references to specific processor information (GPPs).")
    steps: List[Step] = Field(..., title="Steps", description="A list of all (known) steps needed to produce the data object of interest.")
    missing: List[str] = Field(..., title="Missing Information", description="A list of references for which there is no further information avaialable. This is either due to the fact that not all provenance information is known to the node or because of first order data objects, i.e., data objects that have not been generated but uploaded to the DOR.")


class DataObject(BaseModel):
    """
    General meta information about a data object.
    """
    class CreationDetails(BaseModel):
        """
        Details about who created the data object and when.
        """
        timestamp: int = Field(..., title="Timestamp", description="The time of creation in millisecond (UTC) since the beginning of the epoch.", example=1664849510076)
        creators_iid: List[str] = Field(..., title="Creators", description="A list of ids belong to the identities of the creators.", example="[vx4a3180m97msbi3q11xtcav6v65swoi34bvqggvtj0itzsbargbuxdzzok7xjz2]")

    class Tag(BaseModel):
        """
        Tags are key/value pairs. Keys are strings while values can be basic types (`str`, `int`, `float`, `bool`)
        and JSON-compatible complex types (`List` and `Dict`).
        """
        key: str = Field(..., title="Key", description="The key of the tag.", example="module")
        value: Optional[Union[str, int, float, bool, List, Dict]] = Field(title="Value", description="The value of the tag", example="D1.2")

    obj_id: str = Field(..., title="Object Id", description="The id of the data object.", example="f25c8b96679aaf74eb41b17fbf7951d790423b6208a5d0efb1cd2a124c1f9cb4")
    c_hash: str = Field(..., title="Content Hash", description="The content hash of the data object.", example="9ab2253fc38981f5be9c25cf0a34b62cdf334652344bdef16b3d5dbc0b74f2f1")
    data_type: str = Field(..., title="Data Type", description="The data type of the data object.", example="JSONObject")
    data_format: str = Field(..., title="Data Format", description="The data format of the data object.", example="json")
    created: CreationDetails = Field(..., title="Creation Details", description="Information about the creation of this data object.")
    owner_iid: str = Field(..., title="Owner IId", description="Owner IId", example="vx4a3180m97msbi3q11xtcav6v65swoi34bvqggvtj0itzsbargbuxdzzok7xjz2")
    access_restricted: bool = Field(..., title="Access Restriction", description="Indicates if this data object has restricted access to its content.", example=False)
    access: List[str] = Field(..., title="Access", description="A list of ids of identities that have access to the contents of the data object.", example=["vx4a3180m97msbi3q11xtcav6v65swoi34bvqggvtj0itzsbargbuxdzzok7xjz2"])
    tags: Dict[str, Union[str, int, float, bool, List, Dict]] = Field(..., title="Tags", description="The tags of this data object.")
    last_accessed: int = Field(..., title="Last Accessed", description="The timestamp (in UTC milliseconds since the beginning of the epoch) when the data object has been accessed the last time.", example=1664849510076)
    custodian: Optional[NodeInfo] = Field(title='Custodian', description="Information about the node that hosts this data object.")


class GPPDataObject(DataObject):
    """
    Meta information specific to a GPP data object.
    """
    gpp: GitProcessorPointer = Field(..., title="GPP", description="The Git Processor Pointer for the data object.")


class CDataObject(DataObject):
    """
    Meta information specific to a content data object.
    """
    class License(BaseModel):
        """
        Basic licensing information, following Creative Commons. Boolean flags are used to indicate whether the
        creators of a data object have to be credited, whether derivative work should be shared alike (i.e., with
        the same license), whether commercial use is prohibited and whether creation of derivatives is allowed.
        """
        by: bool = Field(..., title="Credit Creators", description="Indicates if creators must be credited.", example=True)
        sa: bool = Field(..., title="Share Alike", description="Indicates if derivatives must be shared alike.", example=False)
        nc: bool = Field(..., title="Non-Commercial", description="Indicates if commercial use is prohibited.", example=False)
        nd: bool = Field(..., title="Non-Derive", description="Indicates if creating derivatives is prohibited.", example=False)

    content_encrypted: bool = Field(..., title="Content Encrypted", description="Indicates if the content of the data object is encrypted.", example=False)
    license: License = Field(..., title="License", description="The license information for this data object.")
    recipe: Optional[DataObjectRecipe] = Field(title="Recipe", description="If this data object has been produced by a processor, a recipe is provided. Data objects that are uploaded by users typically do not come with a recipe unless the user provides one manually when uploading the content to the DOR.")


class SearchParameters(BaseModel):
    """
    Search parameters.
    """
    patterns: Optional[List[str]] = Field(title="Patterns", description="Search patterns.")
    owner_iid: Optional[str] = Field(title="Owner IId", description="Constraint: only data objects that are owned by this identity.")
    data_type: Optional[str] = Field(title="Data Type", description="Constraint: only data objects that match the data type.")
    data_format: Optional[str] = Field(title="Data Format", description="Constraint: only data objects that match the data format.")
    c_hashes: Optional[List[str]] = Field(title="Content Hashes", description="Constraint: only data objects that have matching content hashes.")


class AddDataObjectParameters(BaseModel):
    """
    General parameters for adding a new data object.
    """
    owner_iid: str = Field(..., title="Owner IId", description="The id of the identity that should be assigned ownership to this data object.")
    creators_iid: List[str] = Field(..., title="", description="")


class AddGPPDataObjectParameters(AddDataObjectParameters):
    """
    Parameters for creating a new GPP data object.
    """
    source: str = Field(..., title="Source", description="The source where the code can be found. Typically, this is a URL pointing at a Github repository.", example="https://github.com/the-repo")
    commit_id: str = Field(..., title="Commit Id", description="The commit id to be used. This allows to refer to a specific version of the code.", example="833e8f7")
    proc_path: str = Field(..., title="", description="The relative path in the repository where the processor can be found.", example="/processor/proc_simulator")
    proc_config: str = Field(..., title="", description="The configuration that should be used.", example="default")
    github_credentials: Optional[GithubCredentials] = Field(title="Github Credentials", description="The credentials needed to access the Github repository that contains the code for the processor. This information is not needed if the repository is public.")


class AddCDataObjectParameters(AddDataObjectParameters):
    """
    Parameters for creating a new content data object.
    """
    data_type: str = Field(..., title="Data Type", description="The data type of the data object.")
    data_format: str = Field(..., title="Data Format", description="The data format of the data object.")
    access_restricted: bool = Field(..., title="Access Restricted", description="Indicates if the access to this data object should be restricted.")
    content_encrypted: bool = Field(..., title="Content Encrypted", description="Indicates if the content has been encrypted.")
    license: CDataObject.License = Field(..., title="License", description="License information for this data object.")
    recipe: Optional[DataObjectRecipe] = Field(title="Recipe", description="Recipe for this data object (if any).")
