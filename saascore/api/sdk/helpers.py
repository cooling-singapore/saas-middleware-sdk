import os
import time
from typing import Union, Optional

from flask import send_from_directory, jsonify
from requests import Response

from saascore.api.sdk.exceptions import UnexpectedHTTPError, MalformedResponseError, UnsuccessfulRequestError
from saascore.cryptography.helpers import hash_string_object, hash_json_object, hash_bytes_object
from saascore.helpers import validate_json
from saascore.keystore.identity import Identity
from saascore.keystore.keystore import Keystore

error_response_schema = {
    'type': 'object',
    'properties': {
        'reason': {'type': 'string'},
        'exception_id': {'type': 'string'},
        'details': {'type': 'string'}
    },
    'required': ['reason', 'exception_id']
}


def sign_authorisation_token(authority: Keystore,
                             url: str, body: dict = None, precision: int = 5) -> str:
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


def verify_authorisation_token(identity: Identity, signature: str,
                               url: str, body: dict = None, precision: int = 5) -> bool:
    # determine time slots (we allow for some variation before and after)
    ref = int(time.time() / precision)
    slots = [ref - 1, ref, ref + 1]

    # generate the token for each time slot and check if for one the signature is valid.
    for slot in slots:
        # logger.info("verify_authorisation_token\tH(url)={}".format(hash_json_object(url).hex()))
        token = hash_string_object(url).hex()

        if body:
            # logger.info("verify_authorisation_token\tH(body)={}".format(hash_json_object(body).hex()))
            token += hash_json_object(body).hex()

        # logger.info("verify_authorisation_token\tH(bytes(slot))={}".format(hash_bytes_object(bytes(slot)).hex()))
        token += hash_bytes_object(bytes(slot)).hex()

        # logger.info("verify_authorisation_token\tH(self.public_as_string())={}".format(
        #     hash_string_object(self.public_as_string()).hex()))
        token += hash_string_object(identity.s_public_key_as_string()).hex()

        token = hash_string_object(token)
        # logger.info("verify_authorisation_token\ttoken={}".format(token.hex()))

        if identity.verify(token, signature):
            return True

    # no valid signature for any of the eligible timeslots
    return False


def create_ok_response(content: Union[dict, list] = None) -> (Response, int):
    """
    Creates an 'Ok' response envelope containing an optional response.
    :param content: (optional) response content
    :return: response
    """
    return jsonify(content if content else {}), 200


def create_ok_attachment(content_path: str) -> (Response, int):
    """
    Creates a response that streams the contents of a file.
    :param content_path: the path of the file
    :return:
    """
    head, tail = os.path.split(content_path)
    return send_from_directory(head, tail, as_attachment=True), 200


def create_error_response(reason: str, exception_id: str, details: str = None) -> (Response, int):
    """
    Creates an 'Error' response envelope containing information about the error.
    :param reason: the reason as string
    :param exception_id: the unique id of the exception
    :param details: (optional) details about the error
    :return: response envelope
    """
    content = {
        'status': 'error',
        'reason': reason,
        'exception_id': exception_id,
    }

    if details is not None:
        content['details'] = details

    return jsonify(content), 500


def extract_response(response: Response) -> Optional[Union[dict, list]]:
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
        # validate the JSON content
        content = response.json()
        if not validate_json(content, schema=error_response_schema):
            raise MalformedResponseError({
                'content': content
            })

        raise UnsuccessfulRequestError(content['reason'],
                                       content['exception_id'],
                                       content['details'] if 'details' in content else None
                                       )

    else:
        raise UnexpectedHTTPError({
            'response': response
        })
