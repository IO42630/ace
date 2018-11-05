import aiohttp

from typing import List
from cbor2 import dumps, loads
from lib.cbor.constants import Keys as CK, GrantTypes
from lib.cose.constants import Key as Cose
from lib.cose import CoseKey
from lib.edhoc import Client as EdhocClient

from lib.ace.client.ace_session import AceSession


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


class HTTPClient(Client):

    def __init__(self, client_id: str, client_secret: bytes):
        super().__init__(client_id, client_secret)
        self.client = aiohttp.ClientSession()
    
    async def establish_oscore_context(self, session: AceSession, rs_url: str):
        send = lambda message: (
            self.client.post(f'{rs_url}/.well-known/edhoc', data=message)
        )

        message1 = session.edhoc_client.initiate_edhoc()
        async with send(bytes(message1)) as resp:
            message2 = await resp.read()
        message3 = session.edhoc_client.continue_edhoc(message2)
        await send(bytes(message3))

        return session.edhoc_client.session.oscore_context
    
    async def upload_access_token(self, session: AceSession, rs_url: str, endpoint: str):
        async with self.client.post(f'{rs_url}{endpoint}', data=session.token) as resp:
            assert resp.status == 201

    async def access_resource(self, session: AceSession, rs_url: str, endpoint: str):
        """
        Access protected resource
        :param url: The URL to the protected resource
        :param session: The ACE session to use
        :return: Response from the protected resource
        """
        await self.ensure_oscore_context(session, rs_url)

        data = session.oscore_context.encrypt(b'')
        async with self.client.get(f"{rs_url}{endpoint}", data=data) as resp:
            assert resp.status == 200
            payload = await resp.read()

        decrypted_response = session.oscore_context.decrypt(payload)

        return loads(decrypted_response)

    async def post_resource(self, session: AceSession, rs_url: str, endpoint: str, data: bytes):
        await self.ensure_oscore_context(session, rs_url)
        payload = session.oscore_context.encrypt(data)

        async with self.client.post(f"{rs_url}{endpoint}", data=payload) as resp:
            assert resp.status == 201
            payload = await resp.read()
        
        decrypted_response = session.oscore_context.decrypt(payload)

        return loads(decrypted_response)
