from datetime import datetime

from saas.rest.proxy import EndpointProxy
from saas.rest.schemas import Token


class AppProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int), endpoint_prefix: str, username: str, password: str):
        super().__init__(endpoint_prefix, remote_address)

        self._username = username
        self._password = password
        self._token = None
        self._expiry = None

    def _refresh_token(self) -> None:
        data = {
            'grant_type': 'password',
            'username': self._username,
            'password': self._password
        }

        # get the token
        result = self.auth_post('/token', data=data)
        self._token = Token.parse_obj(result)

    @property
    def token(self) -> Token:
        now = int(datetime.utcnow().timestamp())
        if self._token is None or now > self._token.expiry - 60:
            self._refresh_token()
        return self._token
