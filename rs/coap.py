import asyncio
import random

import aiocoap
from aiocoap import resource, Context
from cbor2 import dumps, loads

import lib.cwt as cwt
from lib.cbor.constants import Keys as CK
from lib.cose import CoseKey
from lib.cose.constants import Key as Cose
from lib.cose.cose import SignatureVerificationFailed
from lib.edhoc import Server as EdhocServer

from . import AS_PUBLIC_KEY, RS_PRIVATE_KEY, ResourceServer


class TemperatureResource(resource.Resource):

    def __init__(self, token_cache, resource_server):
        super().__init__()
        self.token_cache = token_cache
        self.resource_server = resource_server

    async def render_get(self, request):
        token = self.token_cache.get_token()

        print(self.resource_server.edhoc_server.oscore_context)

        # Verify scope
        if token[CK.SCOPE] != 'read_temperature':
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED)

        temperature = random.randint(8, 42)

        response = self.resource_server.edhoc_server.encrypt(dumps({'temperature': f"{temperature}C"}))

        return aiocoap.Message(payload=response)


class AuthzInfoResource(resource.Resource):

    def __init__(self, token_cache, resource_server):
        super().__init__()
        self.token_cache = token_cache
        self.resource_server = resource_server

    async def render_post(self, request):
        access_token = request.payload

        # introspect_payload = self.introspect(access_token)

        # Verify if valid CWT from AS
        try:
            decoded = cwt.decode(access_token, key=AS_PUBLIC_KEY)

        except SignatureVerificationFailed as err:
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED)

        # Check if audience claim in token matches audience identifier of this resource server
        if decoded[CK.AUD] != self.resource_server.audience:
            return aiocoap.Message(code=aiocoap.FORBIDDEN)

        # Extract PoP Key
        pop_key = CoseKey.from_cose(decoded[CK.CNF][Cose.COSE_KEY])

        self.token_cache.add_token(token=decoded, pop_key=pop_key)

        # Prepare Edhoc Server
        self.resource_server.edhoc_server = EdhocServer(RS_PRIVATE_KEY, pop_key.key)

        return aiocoap.Message(code=aiocoap.CREATED)


class EdhocResource(resource.Resource):

    def __init__(self, token_cache, resource_server):
        super().__init__()
        self.token_cache = token_cache
        self.resource_server = resource_server

    async def render_post(self, request):
        message = request.payload

        response = self.resource_server.edhoc_server.on_receive(message)

        return aiocoap.Message(code=aiocoap.CREATED, payload=bytes(response))


class CoAPResourceServer(ResourceServer):

    def __init__(self, audience, client_id=None, client_secret=None):
        ResourceServer.__init__(self, audience, client_id=None, client_secret=None)
        self.site = resource.Site()
        self.site.add_resource(('temperature',), TemperatureResource(self.token_cache, self))
        self.site.add_resource(('authz-info',), AuthzInfoResource(self.token_cache, self))
        self.site.add_resource(('.well-known', 'edhoc'), EdhocResource(self.token_cache, self))


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    server = CoAPResourceServer("tempSensor0")
    asyncio.ensure_future(Context.create_server_context(server.site), loop=loop)
    loop.run_forever()
