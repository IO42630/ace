import asyncio
from cbor2 import dumps
from aiocoap import Context

from lib.ace.client.coap import CoAPClient

AS_URL = 'http://localhost:8080'
RS_URL = 'coap://localhost'


async def main():
    protocol = await Context.create_client_context()
    client = CoAPClient(
        client_id='ace_client_1',
        client_secret=b'ace_client_1_secret_123456',
        protocol=protocol
    )

    # Request access token
    session = await client.request_access_token(
        as_url=AS_URL,
        audience="tempSensor0",
        scopes=["read_temperature", "post_led"]
    )

    # Upload token to RS
    await client.upload_access_token(session, RS_URL, '/authz-info')

    # Access temperature resource
    response = await client.access_resource(session, RS_URL, '/temperature')
    print(f"Response: {response}")


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
