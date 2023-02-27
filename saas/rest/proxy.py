import json
import time
from datetime import datetime
from typing import Union, Optional, BinaryIO

import requests
from snappy import snappy

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import hash_string_object, hash_json_object, hash_bytes_object
from saas.core.keystore import Keystore
from saas.rest.exceptions import UnexpectedHTTPError, UnsuccessfulRequestError, UnexpectedContentType, \
    UnsuccessfulConnectionError
from saas.rest.schemas import Token


def extract_response(response: requests.Response) -> Optional[Union[dict, list]]:
    """
    Extracts the response content in case of an 'Ok' response envelope or raises an exception in case
    of an 'Error' envelope.
    :param response: the response message
    :return: extracted response content (if any)
    :raise UnsuccessfulRequestError
    """

    if response.status_code == 200:
        return response.json()

    elif response.status_code == 500:
        try:
            content = response.json()
            raise UnsuccessfulRequestError(
                content['reason'], content['id'], content['details'] if 'details' in content else None
            )

        except Exception:
            raise SaaSRuntimeException(response.reason, details={
                'status_code': response.status_code
            })

    else:
        raise UnexpectedHTTPError({
            'response': response
        })


def generate_authorisation_token(authority: Keystore, url: str, body: dict = None, precision: int = 5) -> str:
    slot = int(time.time() / precision)

    # logger.info("sign_authorisation_token\tH(url)={}".format(hash_json_object(url).hex()))
    token = hash_string_object(url).hex()

    if body:
        # logger.info("sign_authorisation_token\tH(body)={}".format(hash_json_object(body).hex()))
        token += hash_json_object(body).hex()

    # logger.info("sign_authorisation_token\tH(bytes(slot))={}".format(hash_bytes_object(bytes(slot)).hex()))
    token += hash_bytes_object(bytes(slot)).hex()

    # logger.info("sign_authorisation_token\tH(self.public_as_string())={}".format(hash_string_object(self.public_as_string()).hex()))
    token += hash_string_object(authority.signing_key.public_as_string()).hex()

    token = hash_string_object(token)
    # logger.info("sign_authorisation_token\ttoken={}".format(token.hex()))

    return authority.sign(token)


def _make_headers(url: str, body: Union[dict, list] = None, authority: Keystore = None,
                  token: Token = None) -> dict:

    headers = {}

    if authority:
        headers['saasauth-iid'] = authority.identity.id
        headers['saasauth-signature'] = generate_authorisation_token(authority, url, body)

    if token:
        headers['Authorization'] = f"Bearer {token.access_token}"

    return headers


class Snapper:
    def __init__(self, source: BinaryIO, chunk_size: int = 1024*1024) -> None:
        self._source = source
        self._chunk_size = chunk_size

    def read(self) -> bytes:
        buffer = bytearray()
        while True:
            chunk = self._source.read(self._chunk_size)
            if not chunk:
                return bytes(buffer)
            chunk = snappy.compress(chunk)

            chunk_length = len(chunk)
            buffer.extend(chunk_length.to_bytes(4, byteorder='big'))
            buffer.extend(chunk)


class Session:
    def __init__(self, remote_address: (str, int), credentials: (str, str)) -> None:
        self._remote_address = remote_address
        self._credentials = credentials

        self._token = None
        self._expiry = None

    @property
    def address(self) -> (str, int):
        return self._remote_address

    @property
    def credentials(self) -> (str, str):
        return self._credentials

    def refresh_token(self) -> None:
        data = {
            'grant_type': 'password',
            'username': self._credentials[0],
            'password': self._credentials[1]
        }

        # get the token
        result = self._auth_post('/token', data=data)
        self._token = Token.parse_obj(result)

    @property
    def token(self) -> Token:
        now = int(datetime.utcnow().timestamp())
        if self._token is None or now > self._token.expiry - 60:
            self.refresh_token()
        return self._token

    def _auth_post(self, endpoint: str, data=None) -> dict:
        url = f"http://{self._remote_address[0]}:{self._remote_address[1]}{endpoint}"

        try:
            response = requests.post(url, data=data)
            return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)


class EndpointProxy:
    def __init__(self, endpoint_prefix: str, remote_address: (str, int), credentials: (str, str) = None) -> None:
        self._endpoint_prefix = endpoint_prefix
        self._remote_address = remote_address
        self._session = Session(remote_address, credentials) if credentials else None

    @property
    def remote_address(self) -> (str, int):
        return self._remote_address

    @property
    def session(self) -> Session:
        return self._session

    def get(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, download_path: str = None,
            with_authorisation_by: Keystore = None) -> Optional[Union[dict, list]]:

        url = self._make_url(endpoint, parameters)
        headers = _make_headers(f"GET:{url}", body=body, authority=with_authorisation_by,
                                token=self._session.token if self._session else None)

        try:
            if download_path:
                with requests.get(url, headers=headers, json=body, stream=True) as response:
                    header = {k.lower(): v for k, v in response.headers.items()}
                    if header['content-type'] == 'application/json':
                        return extract_response(response)

                    elif response.headers['content-type'] == 'application/octet-stream':
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
                response = requests.get(url, headers=headers, json=body)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def put(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, attachment_path: str = None,
            with_authorisation_by: Keystore = None, use_snappy: bool = True) -> Union[dict, list]:

        url = self._make_url(endpoint, parameters)
        headers = _make_headers(f"PUT:{url}", body=body, authority=with_authorisation_by,
                                token=self._session.token if self._session else None)

        try:
            if attachment_path:
                with open(attachment_path, 'rb') as f:
                    response = requests.put(url,
                                            headers=headers,
                                            data={'body': json.dumps(body)} if body else None,
                                            files={'attachment': Snapper(f) if use_snappy else f}
                                            )

                    return extract_response(response)

            else:
                response = requests.put(url, headers=headers, json=body)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def post(self, endpoint: str, body: Union[dict, list, str] = None, data=None, parameters: dict = None,
             attachment_path: str = None, with_authorisation_by: Keystore = None,
             use_snappy: bool = True) -> Union[dict, list]:

        url = self._make_url(endpoint, parameters)
        headers = _make_headers(f"POST:{url}", body=body, authority=with_authorisation_by,
                                token=self._session.token if self._session else None)

        try:
            if attachment_path:
                with open(attachment_path, 'rb') as f:
                    response = requests.post(url,
                                             headers=headers,
                                             data={'body': json.dumps(body)} if body else None,
                                             files={'attachment': Snapper(f) if use_snappy else f}
                                             )

                    return extract_response(response)

            else:
                response = requests.post(url, headers=headers, data=data, json=body)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def delete(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None,
               with_authorisation_by: Keystore = None) -> Union[dict, list]:

        url = self._make_url(endpoint, parameters)
        headers = _make_headers(f"DELETE:{url}", body=body, authority=with_authorisation_by,
                                token=self._session.token if self._session else None)

        try:
            response = requests.delete(url, headers=headers, json=body)
            return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def _make_url(self, endpoint: str, parameters: dict = None) -> str:
        url = f"http://{self._remote_address[0]}:{self._remote_address[1]}{self._endpoint_prefix}{endpoint}"
        if parameters:
            eligible = {}
            for k, v in parameters.items():
                if k is not None and v is not None:
                    eligible[k] = v

            if eligible:
                url += '?' + '&'.join(f"{k}={v}" for k, v in eligible.items())

        return url
