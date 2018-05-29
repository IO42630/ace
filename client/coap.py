from . import Client, AS_URL

from cbor2 import dumps, loads
import aiocoap
from aiocoap import Context, GET, POST
import asyncio

from lib.edhoc import Client as EdhocClient

RS_URL = 'coap://localhost'

loop = asyncio.get_event_loop()


class CoAPClient(Client):

    def __init__(self, client_id: str, client_secret: bytes, protocol):
        super().__init__(client_id, client_secret)
        self.protocol = protocol

    async def upload_access_token(self, url):
        request = aiocoap.Message(code=POST, uri=f'{url}/authz-info', payload=self.session.token)
        try:
            response = await self.protocol.request(request).response
        except Exception as e:
            raise(e)
        else:
            print(f'{url}/authz-info')
            print(response.code)
            assert response.code == aiocoap.CREATED


    async def establish_secure_context(self, url):
        edhoc_client = EdhocClient(self.session.private_key, self.session.rs_public_key)

        def send(message):
            request = aiocoap.Message(code=POST, uri=f'{url}/.well-known/edhoc', payload=message)
            return self.protocol.request(request)

        message1 = edhoc_client.initiate_edhoc()
        response = await send(bytes(message1)).response
        message2 = response.payload
        message3 = edhoc_client.continue_edhoc(message2)
        await send(bytes(message3)).response
        print(edhoc_client.oscore_context)

        return edhoc_client

    async def access_resource(self, edhoc_client, url):
        request = aiocoap.Message(code=GET, uri=url)
        response = await self.protocol.request(request).response
        assert response.code == aiocoap.CONTENT
        decrypted_response = edhoc_client.decrypt(response.payload)

        return loads(decrypted_response)


async def main():
    protocol = await Context.create_client_context()
    client = CoAPClient(client_id='ace_client_1',
                    client_secret=b'ace_client_1_secret_123456',
                    protocol=protocol)

    client.start_new_session()

    await client.request_access_token(AS_URL)
    await client.upload_access_token(RS_URL)
    edhoc_session = await client.establish_secure_context(RS_URL)

    response = await client.access_resource(edhoc_session, RS_URL + '/temperature')
    print(f"Resource: {response}")

    data = 1
    response = await client.post_resource(edhoc_session, RS_URL + '/led', dumps(data))
    print(f"Resource: {response}")


if __name__ == "__main__":
    loop.run_until_complete(main())
