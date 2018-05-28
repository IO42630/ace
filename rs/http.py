import asyncio
import random

from aiohttp import web
from aiohttp.abc import AbstractRouter
from cbor2 import dumps, loads

import lib.cwt as cwt
from lib.cbor.constants import Keys as CK
from lib.cose import CoseKey
from lib.cose.constants import Key as Cose
from lib.cose.cose import SignatureVerificationFailed
from lib.edhoc import Server as EdhocServer

from . import AS_PUBLIC_KEY, RS_PRIVATE_KEY, ResourceServer


class HTTPResourceServer(ResourceServer):

    def __init__(self, audience, router: AbstractRouter, client_id=None, client_secret=None):
        super().__init__(audience, client_id=None, client_secret=None)
        router.add_get('/temperature', self.get_temperature)
        router.add_get('/audience', self.get_audience)
        router.add_post('/authz-info', self.authz_info)
        router.add_post('/.well-known/edhoc', self.edhoc)

    async def edhoc(self, request):
        message = await request.content.read()

        response = self.edhoc_server.on_receive(message)

        return web.Response(status=201, body=bytes(response))

    # GET /temperature
    async def get_temperature(self, request):
        token = self.token_cache.get_token()

        print(self.edhoc_server.oscore_context)

        # Verify scope
        if token[CK.SCOPE] != 'read_temperature':
            return web.Response(status=401, body=dumps({'error': 'not authorized'}))

        temperature = random.randint(8, 42)

        response = self.edhoc_server.encrypt(dumps({'temperature': f"{temperature}C"}))

        return web.Response(status=200, body=response)

    async def get_audience(self, request):
        return self.audience

    # POST /authz_info
    async def authz_info(self, request):
        # Extract access token
        access_token = await request.content.read()

        # introspect_payload = self.introspect(access_token)

        # Verify if valid CWT from AS
        try:
            decoded = cwt.decode(access_token, key=AS_PUBLIC_KEY)

        except SignatureVerificationFailed as err:
            return web.Response(status=401, body=dumps({'error': str(err)}))

        # Check if audience claim in token matches audience identifier of this resource server
        if decoded[CK.AUD] != self.audience:
            return web.Response(status=403, body=dumps({'error': 'Audience mismatch'}))

        # Extract PoP Key
        pop_key = CoseKey.from_cose(decoded[CK.CNF][Cose.COSE_KEY])

        self.token_cache.add_token(token=decoded, pop_key=pop_key)

        # Prepare Edhoc Server
        self.edhoc_server = EdhocServer(RS_PRIVATE_KEY, pop_key.key)

        return web.Response(status=201)


loop = asyncio.get_event_loop()
app = web.Application(loop=loop)
server = HTTPResourceServer("tempSensor0", app.router)
web.run_app(app, host='localhost', port=8081)
