import time

from saascore.cryptography.helpers import hash_string_object, hash_json_object, hash_bytes_object
from saascore.keystore.identity import Identity
from saascore.keystore.keystore import Keystore


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


def verify_authorisation_token(identity: Identity, signature: str, url: str, body: dict = None, precision: int = 5) -> bool:
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
