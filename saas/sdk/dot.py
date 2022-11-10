import abc
import numpy as np

from typing import Dict, List
from pydantic import BaseModel

from saas.core.exceptions import ExceptionContent
from saas.core.helpers import generate_random_string


class BoundingBox(BaseModel):
    west: float
    north: float
    east: float
    south: float


class Dimensions(BaseModel):
    width: int
    height: int


class DOTResultContext(abc.ABC):
    @abc.abstractmethod
    def caz_mask(self, bounding_box: BoundingBox, dimensions: Dimensions) -> np.ndarray:
        ...


class DOTRuntimeError(Exception):
    def __init__(self, reason: str, details: dict = None):
        self._content = ExceptionContent(id=generate_random_string(16), reason=reason, details=details)

    @property
    def id(self):
        return self._content.id

    @property
    def reason(self):
        return self._content.reason

    @property
    def details(self):
        return self._content.details

    @property
    def content(self) -> ExceptionContent:
        return self._content


class DataObjectType(abc.ABC):
    @abc.abstractmethod
    def data_type(self) -> str:
        pass

    @abc.abstractmethod
    def supported_formats(self) -> List[str]:
        pass

    @abc.abstractmethod
    def extract_feature(self, content_path: str, parameters: dict, context: DOTResultContext) -> Dict:
        pass