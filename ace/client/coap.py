from cbor2 import dumps, loads
import aiocoap
from aiocoap import Context, GET, POST

from ace.client import Client, AceSession


class CoAPClient(Client):

    def __init__(self, client_id: str, client_secret: bytes, protocol):
        super().__init__(client_id, client_secret)
        self.protocol = protocol

    async def upload_access_token(self, session: AceSession, rs_url: str, endpoint: str):
        request = aiocoap.Message(code=POST, uri=f'{rs_url}{endpoint}', payload=session.token)
        try:
            response = await self.protocol.request(request).response
        except Exception as e:
            raise(e)
        else:
            assert response.code == aiocoap.CREATED

    async def establish_oscore_context(self, session: AceSession, rs_url: str):
        def send(message):
            request = aiocoap.Message(code=POST, uri=f'{rs_url}/.well-known/edhoc', payload=message)
            return self.protocol.request(request)

        message1 = session.edhoc_client.initiate_edhoc()
        resp = await send(bytes(message1)).response
        message2 = resp.payload
        message3 = session.edhoc_client.continue_edhoc(message2)
        send(bytes(message3))
        # TODO wait and check message 3 response

        return session.edhoc_client.session.oscore_context

    async def access_resource(self, session: AceSession, rs_url: str, endpoint: str):
        await self.ensure_oscore_context(session, rs_url)

        payload = session.oscore_context.encrypt(b'')
        request = aiocoap.Message(code=GET, uri=f"{rs_url}{endpoint}", payload=payload)
        response = await self.protocol.request(request).response
        assert response.code == aiocoap.CONTENT

        decrypted_response = session.oscore_context.decrypt(response.payload)

        return loads(decrypted_response)

    async def put_resource(self, session: AceSession, rs_url: str, endpoint: str, data: bytes):
        await self.ensure_oscore_context(session, rs_url)
        
        payload = session.oscore_context.encrypt(data)
        request = aiocoap.Message(code=POST, uri=f"{rs_url}{endpoint}", payload=payload)
        response = await self.protocol.request(request).response
        assert response.code == aiocoap.CONTENT
        
        decrypted_response = session.oscore_context.decrypt(payload)

        return loads(decrypted_response)

    async def post_resource(self,
                            session: AceSession,
                            rs_url: str,
                            endpoint: str, data: bytes):
        await self.ensure_oscore_context(session, rs_url)

        payload = session.oscore_context.encrypt(data)
        request = aiocoap.Message(code = aiocoap.numbers.codes.Code.POST,
                                  uri = f"{rs_url}{endpoint}",
                                  payload = payload)
        response = await self.protocol.request(request).response
        assert response.code == aiocoap.CONTENT
        decrypted_response = session.oscore_context.decrypt(response.payload)

        return loads(decrypted_response)