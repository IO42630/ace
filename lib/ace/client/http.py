from cbor2 import dumps, loads
import aiohttp

from lib.ace.client import Client, AceSession


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
