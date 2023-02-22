from dataclasses import dataclass
from typing import Any, Optional, Sequence

from pydantic import BaseModel


@dataclass
class EndpointDefinition:
    method: str
    prefix: str
    rule: str
    function: Any
    response_model: Any
    dependencies: Optional[Sequence[Any]]


class Token(BaseModel):
    access_token: str
    token_type: str
    expiry: int
