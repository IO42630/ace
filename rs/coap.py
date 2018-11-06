import asyncio
import random

import aiocoap
from aiocoap import resource, Context
from cbor2 import dumps, loads
from ecdsa import SigningKey, VerifyingKey

from lib.ace.rs.coap import CoAPResourceServer
from lib.ace.rs import NotAuthorizedException


class TemperatureResource(resource.Resource):

    def __init__(self, scope, resource_server):
        super().__init__()
        self.scope = scope
        self.resource_server = resource_server

    async def render_get(self, request):
        prot, unprot, cipher = loads(request.payload).value
        try:
            oscore_context = self.resource_server.oscore_context(unprot, self.scope)
        except NotAuthorizedException:
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED)

        temperature = random.randint(8, 42)

        response = oscore_context.encrypt(dumps({'temperature': f"{temperature}C"}))

        return aiocoap.Message(payload=response)


class TemperatureServer(CoAPResourceServer):

    def __init__(self,
                 audience: str,
                 identity: SigningKey,
                 as_url: str,
                 as_public_key: VerifyingKey,
                 site,
                 client_id=None,
                 client_secret=None):
        super().__init__(audience, identity, as_url, as_public_key, site, client_id, client_secret)
        self.site.add_resource(('temperature',), TemperatureResource("read_temperature", self))


if __name__ == "__main__":
    from ecdsa import VerifyingKey, SigningKey

    rs_identity = SigningKey.from_der(
        bytes.fromhex(
            "307702010104200ffc411715d3cc4917bd27ac4f310552b085b1ca0bb0a8"
            "bbb9d8931d651544c1a00a06082a8648ce3d030107a144034200046cc415"
            "12d92fb03cb3b35bed5b494643a8a8a55503e87a90282c78d6c58a7e3c88"
            "a21c0287e7e8d76b0052b1f1a2dcebfea57714c1210d42f17b335adcb76d"
            "7a"
        )
    )

    as_public_key = VerifyingKey.from_der(
        bytes.fromhex(
            "3059301306072a8648ce3d020106082a8648ce3d030107034200047069be"
            "d49cab8ffa5b1c820271aef0bc0c8f5cd149e05c5b9e37686da06d02bd5f"
            "7bc35ea8265be7c5e276ad7e7d0eb05e4a0551102a66bba88b02b5eb4c33"
            "55"
        )
    )

    loop = asyncio.get_event_loop()
    root = resource.Site()
    server = TemperatureServer(
        audience="tempSensor0",
        identity=rs_identity,
        as_url='http://localhost:8080',
        as_public_key=as_public_key,
        site=root
    )
    asyncio.ensure_future(Context.create_server_context(server.site), loop=loop)
    loop.run_forever()
