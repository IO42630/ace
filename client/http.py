from . import Client, AS_URL

from cbor2 import dumps, loads
import aiohttp
import asyncio

from lib.edhoc import Client as EdhocClient

#RS_URL = 'http://192.168.0.59:8000'
RS_URL = 'http://localhost:8081'


class HTTPClient(Client):

    def __init__(self, client_id: str, client_secret: bytes):
        super().__init__(client_id, client_secret)
        self.client = aiohttp.ClientSession()

    async def upload_access_token(self, url):
        async with self.client.post(f'{url}/authz-info', data=self.session.token) as resp:
            assert resp.status == 201

    async def establish_secure_context(self):
        edhoc_client = EdhocClient(self.session.private_key, self.session.rs_public_key)

        send = lambda message: (
            self.client.post(f'{RS_URL}/.well-known/edhoc', data=message)
        )

        message1 = edhoc_client.initiate_edhoc()
        async with send(bytes(message1)) as resp:
            message2 = await resp.read()
        message3 = edhoc_client.continue_edhoc(message2)
        await send(bytes(message3))
        print(edhoc_client.oscore_context)

        return edhoc_client

    async def access_resource(self, edhoc_client, url):
        async with self.client.get(url) as resp:
            assert resp.status == 200
            payload = await resp.read()

        decrypted_response = edhoc_client.decrypt(payload)

        return loads(decrypted_response)

    async def post_resource(self, edhoc_client, url, data: bytes):
        # Encrypt payload
        payload = edhoc_client.encrypt(data)

        async with self.client.post(url, data=payload) as resp:
            assert resp.status == 204


async def main():
    client = HTTPClient(client_id='ace_client_1',
                    client_secret=b'ace_client_1_secret_123456')

    client.start_new_session()

    await client.request_access_token(AS_URL)
    await client.upload_access_token(RS_URL)
    edhoc_session = await client.establish_secure_context()

    response = await client.access_resource(edhoc_session, RS_URL + '/temperature')
    print(f"Resource: {response}")

    data = 1
    response = await client.post_resource(edhoc_session, RS_URL + '/led', dumps(data))
    print(f"Resource: {response}")


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
