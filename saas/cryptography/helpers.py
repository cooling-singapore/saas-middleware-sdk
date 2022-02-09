import os
import shutil
from typing import Union

import canonicaljson
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def symmetric_encrypt(content: bytes) -> (bytes, bytes):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    return cipher.encrypt(content), key


def symmetric_decrypt(content: bytes, key: bytes) -> bytes:
    cipher = Fernet(key)
    return cipher.decrypt(content)


def encrypt_file(source_path: str, destination_path: str = None, encrypt_for=None,
                 delete_source: bool = False, chunk_size: int = 1024 * 1024) -> bytes:

    # create key, cipher and encrypt to (temporary) location
    location = destination_path if destination_path else f"{source_path}.enc"
    key = Fernet.generate_key()
    cipher = Fernet(key)
    with open(location, 'wb') as f_out:
        with open(source_path, 'rb') as f_in:
            chunk = f_in.read(chunk_size)
            while chunk:
                chunk = cipher.encrypt(chunk)
                chunk_length = len(chunk)
                length_bytes = chunk_length.to_bytes(4, byteorder='big')

                f_out.write(length_bytes)
                f_out.write(chunk)
                chunk = f_in.read(chunk_size)

    # replace the source file?
    if destination_path is None:
        os.remove(source_path)
        shutil.move(location, source_path)

    # delete the source file (if flag is set)
    elif delete_source:
        os.remove(source_path)

    # do we need to protect the key?
    if encrypt_for is not None:
        key = encrypt_for.encrypt(key).decode('utf-8')

    return key


def decrypt_file(source_path: str, key: bytes, destination_path: str = None, delete_source: bool = False) -> None:
    # create cipher and decrypt to (temporary) location
    cipher = Fernet(key)
    location = destination_path if destination_path else f"{source_path}.dec"
    with open(location, 'wb') as f_out:
        with open(source_path, 'rb') as f_in:
            while True:
                length_bytes = f_in.read(4)
                if not length_bytes:
                    break

                chunk_size = int.from_bytes(length_bytes, 'big')
                chunk = f_in.read(chunk_size)
                chunk = cipher.decrypt(chunk)
                f_out.write(chunk)

    # replace the source file?
    if destination_path is None:
        os.remove(source_path)
        shutil.move(location, source_path)

    # delete the source file (if flag is set)
    elif delete_source:
        os.remove(source_path)


def hash_file_content(path: str) -> bytes:
    """
    Hash the content of a given file using SHA256.
    :param path: the path of the file that is to be hashed
    :return: hash
    """
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

    # read the file in chunks of 64 bytes and update the digest
    with open(path, 'rb') as f:
        data = f.read(64)
        while data:
            digest.update(data)
            data = f.read(64)

    return digest.finalize()


def hash_json_object(obj: Union[dict, list], exclusions: list[str] = None) -> bytes:
    """
    Hash a given JSON object. Before hashing the JSON input is encoded as canonical RFC 7159 JSON.
    :param exclusions:
    :param obj: the JSON object that is to be hashed
    :return: hash
    """

    # make a copy and exclude items (if applicable)
    if isinstance(obj, dict):
        obj = {k: v for k, v in obj.items() if not exclusions or k not in exclusions}
    else:
        obj = [v for v in obj if not exclusions or v not in exclusions]

    # encode the json input as RFC 7159 JSON
    json_input = canonicaljson.encode_canonical_json(obj)

    # use SHA256 to calculate the hash
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(json_input)
    return digest.finalize()


def hash_string_object(obj: str) -> bytes:
    """
    Hash a given string.
    :param obj: the string that is to be hashed
    :return: hash
    """
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(obj.encode('utf-8'))
    return digest.finalize()


def hash_bytes_object(obj: bytes) -> bytes:
    """
    Hash a given byte array.
    :param obj: the byte array that is to be hashed
    :return: hash
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(obj)
    return digest.finalize()
