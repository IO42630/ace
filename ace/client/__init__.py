import aiohttp

from typing import List
from cbor2 import dumps, loads
from ace.cbor.constants import Keys as CK, GrantTypes
from ace.cose.constants import Key as Cose
from ace.cose import CoseKey
from ace.edhoc import Client as EdhocClient

from ace.client.ace_session import AceSession


class Client:

    def __init__(self, client_id: str, client_secret: bytes):
        self.client_id = client_id
        self.client_secret = client_secret
        self.sessions = {}

    async def request_access_token(self, as_url: str, audience: str, scopes: List['str']):
        """
        Request access token from authorization server
        :param as_url: The URL of the authorization server
        :param audience: The audience of the resource server
        :param scopes: The scopes to be accessed
        """
        session = AceSession.create(key_id=bytes(f"{self.client_id}{AceSession.session_id}", 'ascii'))

        pop_key = session.public_pop_key

        payload = {
            CK.GRANT_TYPE:    GrantTypes.CLIENT_CREDENTIALS,
            CK.CLIENT_ID:     self.client_id,
            CK.CLIENT_SECRET: self.client_secret,
            CK.SCOPE:         ",".join(scopes),
            CK.AUD:           audience,
            CK.CNF:           { Cose.COSE_KEY: CoseKey(pop_key, session.pop_key_id, CoseKey.Type.ECDSA).encode() }
        }

        async with aiohttp.request('POST', f'{as_url}/token', data=dumps(payload)) as resp:
            assert resp.status == 200
            body = await resp.read()

        response_content = loads(body)

        token = response_content[CK.ACCESS_TOKEN]
        rs_pub_key = CoseKey.from_cose(response_content[CK.RS_CNF])

        session.token = token
        session.rs_public_key = rs_pub_key.key

        return session

    async def ensure_oscore_context(self, session: AceSession, rs_url: str):
        if session.oscore_context is None:
            session.oscore_context = await self.establish_oscore_context(session, rs_url)

    async def establish_oscore_context(self, session: AceSession, rs_url: str):
        raise NotImplementedError

    async def upload_access_token(self, session: AceSession, rs_url: str, endpoint: str):
        """
        Upload access token to resource server to establish security context
        :param session The ACE session to use
        :param rs_url: The url of the resource server
        :param endpoint: The Authz-Info endpoint path
        """
        raise NotImplementedError

    async def establish_secure_context(self):
        raise NotImplementedError

    async def access_resource(self, edhoc_client, url):
        """
        Access protected resource
        :param url: The URL to the protected resource
        :param session: The ACE session to use
        :return: Response from the protected resource
        """
        raise NotImplementedError

    async def post_resource(self, session: AceSession, rs_url: str, endpoint: str, data: bytes):
        raise NotImplementedError
