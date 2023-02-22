from __future__ import annotations

import os
import string

from threading import Lock
from pydantic import ValidationError

from saas.core.eckeypair import ECKeyPair
from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import hash_json_object
from saas.core.keypair import KeyPair
from saas.core.logging import Logging
from saas.core.rsakeypair import RSAKeyPair
from saas.core.schemas import KeystoreContent
from saas.core.helpers import generate_random_string, write_json_to_file
from saas.core.assets import MasterKeyPairAsset, KeyPairAsset, ContentKeysAsset, SSHCredentialsAsset, \
    GithubCredentialsAsset
from saas.core.identity import generate_identity_token, Identity

logger = Logging.get('saas.core')


class Keystore:
    def __init__(self, path: str, password: str, content: KeystoreContent) -> None:
        self._mutex = Lock()
        self._path = path
        self._password = password
        self._content = content

        self._loaded = {
            'master-key': MasterKeyPairAsset.load(content.assets['master-key'], password)
        }
        self._identity = None

        self._master = self._loaded['master-key'].get()

        # load all other assets
        for key, asset in content.assets.items():
            if key != 'master-key':
                if asset['type'] == KeyPairAsset.__name__:
                    self._loaded[key] = KeyPairAsset.load(asset, self._master)

                elif asset['type'] == ContentKeysAsset.__name__:
                    self._loaded[key] = ContentKeysAsset.load(asset, self._master)

                elif asset['type'] == GithubCredentialsAsset.__name__:
                    self._loaded[key] = GithubCredentialsAsset.load(asset, self._master)

                elif asset['type'] == SSHCredentialsAsset.__name__:
                    self._loaded[key] = SSHCredentialsAsset.load(asset, self._master)

        # keep references to essential keys
        self._s_key = self._loaded['signing-key'].get()
        self._e_key = self._loaded['encryption-key'].get()

        # check if signature is valid
        content_hash = hash_json_object(content.dict(), exclusions=['signature'])
        if not self._s_key.verify(content_hash, content.signature):
            raise SaaSRuntimeException(f"Invalid keystore content signature: "
                                       f"content_hash={content_hash}, signature={content.signature}.")

        self._update_identity()

    @classmethod
    def create(cls, path: str, name: str, email: str, password: str) -> Keystore:
        # create random keystore id
        iid = generate_random_string(64, characters=string.ascii_lowercase+string.digits)

        # create required assets
        master_key = MasterKeyPairAsset(RSAKeyPair.create_new())
        signing_key = KeyPairAsset(ECKeyPair.create_new())
        encryption_key = KeyPairAsset(RSAKeyPair.create_new())
        content_keys = ContentKeysAsset()
        ssh_credentials = SSHCredentialsAsset()
        github_credentials = GithubCredentialsAsset()

        # create the keystore content
        content = {
            'iid': iid,
            'profile': {
                'name': name,
                'email': email
            },
            'nonce': 0,
            'assets': {
                'master-key': master_key.store(password),
                'signing-key': signing_key.store(master_key.get()),
                'encryption-key': encryption_key.store(master_key.get()),
                'content-keys': content_keys.store(master_key.get()),
                'ssh-credentials': ssh_credentials.store(master_key.get()),
                'github-credentials': github_credentials.store(master_key.get())
            }
        }

        # sign the contents of the keystore
        content_hash = hash_json_object(content)
        content['signature'] = signing_key.get().sign(content_hash)

        # create keystore
        keystore_path = os.path.join(path, f"{iid}.json")
        keystore = Keystore(keystore_path, password, KeystoreContent.parse_obj(content))
        keystore.sync()

        logger.info(f"keystore created: id={keystore.identity.id} "
                    f"s_key={keystore._s_key.public_as_string()} "
                    f"e_key={keystore._e_key.public_as_string()}")

        return keystore

    @classmethod
    def load(cls, keystore_path: str, password: str) -> Keystore:
        # check if keystore file exists
        if not os.path.isfile(keystore_path):
            raise SaaSRuntimeException(f"Keystore content not found at {keystore_path}")

        # load content and validate
        try:
            content = KeystoreContent.parse_file(keystore_path)
        except ValidationError:
            raise SaaSRuntimeException("Keystore content not compliant with json schema.")

        # check if we have required assets
        for required in ['master-key', 'signing-key', 'encryption-key', 'content-keys', 'ssh-credentials',
                         'github-credentials']:
            if required not in content.assets:
                raise SaaSRuntimeException(f"Keystore invalid: {required} found.")

        # create keystore
        keystore = Keystore(keystore_path, password, content)
        logger.info(f"keystore loaded: iid={keystore.identity.id} "
                    f"s_key={keystore._s_key.public_as_string()} "
                    f"e_key={keystore._e_key.public_as_string()}")

        return keystore

    @property
    def path(self) -> str:
        with self._mutex:
            return self._path

    @property
    def identity(self) -> Identity:
        with self._mutex:
            return self._identity

    @property
    def encryption_key(self) -> KeyPair:
        with self._mutex:
            return self._e_key

    @property
    def signing_key(self) -> KeyPair:
        with self._mutex:
            return self._s_key

    def update_profile(self, name: str = None, email: str = None) -> Identity:
        with self._mutex:
            if name is not None:
                self._content.profile.name = name

            if email is not None:
                self._content.profile.email = email

        if name or email:
            self.sync()

        return self._identity

    def encrypt(self, content: bytes) -> bytes:
        with self._mutex:
            return self._e_key.encrypt(content, base64_encoded=True)

    def decrypt(self, content: bytes) -> bytes:
        with self._mutex:
            return self._e_key.decrypt(content, base64_encoded=True)

    def sign(self, message: bytes) -> str:
        with self._mutex:
            return self._s_key.sign(message)

    def verify(self, message: bytes, signature: str) -> bool:
        with self._mutex:
            return self._s_key.verify(message, signature)

    @property
    def content_keys(self) -> ContentKeysAsset:
        with self._mutex:
            return self._loaded['content-keys']

    @property
    def ssh_credentials(self) -> SSHCredentialsAsset:
        with self._mutex:
            return self._loaded['ssh-credentials']

    @property
    def github_credentials(self) -> GithubCredentialsAsset:
        with self._mutex:
            return self._loaded['github-credentials']

    def _update_identity(self) -> None:
        # generate valid signature for the identity
        token = generate_identity_token(iid=self._content.iid,
                                        name=self._content.profile.name,
                                        email=self._content.profile.email,
                                        s_public_key=self._s_key.public_as_string(),
                                        e_public_key=self._e_key.public_as_string(),
                                        nonce=self._content.nonce)
        signature = self._s_key.sign(token.encode('utf-8'))

        # update the signature
        self._identity = Identity(id=self._content.iid,
                                  name=self._content.profile.name,
                                  email=self._content.profile.email,
                                  s_public_key=self._s_key.public_as_string(),
                                  e_public_key=self._e_key.public_as_string(),
                                  nonce=self._content.nonce,
                                  signature=signature)

        # verify the identity's integrity
        if not self._identity.verify_integrity():
            raise SaaSRuntimeException(f"Keystore produced invalid identity", details={
                'identity': self._identity
            })

    def sync(self) -> None:
        with self._mutex:
            # increase the nonce
            self._content.nonce += 1

            # serialise all assets
            self._content.assets = {
                key: asset.store(protection=self._password if key == 'master-key' else self._master)
                for key, asset in self._loaded.items()
            }

            # sign the contents of the keystore
            content_hash = hash_json_object(self._content.dict(), exclusions=['signature'])
            self._content.signature = self._s_key.sign(content_hash)

            # write contents to disk
            write_json_to_file(self._content.dict(), self._path)

            # update identity
            self._update_identity()

    def delete(self) -> None:
        with self._mutex:
            os.remove(self._path)