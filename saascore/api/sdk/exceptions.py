from saascore.exceptions import SaaSException


class SDKException(SaaSException):
    """
    Base exception class used for errors originating in the SDK subsystem.
    """


class UnexpectedHTTPError(SDKException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected HTTP error encountered', details=details)


class MalformedRequestError(SDKException):
    def __init__(self, details: dict) -> None:
        super().__init__('Malformed request message', details=details)


class MalformedResponseError(SDKException):
    def __init__(self, details: dict) -> None:
        super().__init__('Malformed response message', details=details)


class UnsuccessfulRequestError(SDKException):
    def __init__(self, reason: str, exception_id: str, details: dict) -> None:
        super().__init__(f"Unsuccessful request: {reason} ({exception_id})", details=details)


class AuthorisationFailedError(SDKException):
    def __init__(self, details: dict) -> None:
        super().__init__('Authorisation failed', details=details)


class UnexpectedContentType(SDKException):
    def __init__(self, details: dict) -> None:
        super().__init__('Unexpected content type', details=details)


class MissingResponseSchemaError(SDKException):
    def __init__(self, details: dict) -> None:
        super().__init__('Response schema is missing', details=details)


class UnsuccessfulConnectionError(SDKException):
    def __init__(self, url: str, details: dict = None) -> None:
        super().__init__(f"Cannot establish connection to '{url}'", details=details)
