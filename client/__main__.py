import asyncio
from cbor2 import dumps
from lib.ace.client.http import HTTPClient

AS_URL = 'http://localhost:8080'
RS_URL = 'http://localhost:8081'


async def main():
    client = HTTPClient(
        client_id='ace_client_1',
        client_secret=b'ace_client_1_secret_123456'
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

    # Update LED resource on RS
    data = { b'led_value': 1 }
    response = await client.post_resource(session, RS_URL, '/led', dumps(data))
    print(f"Response: {response}")

asyncio.get_event_loop().run_until_complete(main())