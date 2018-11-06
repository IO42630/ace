from cbor2 import dumps, loads
from ecdsa import VerifyingKey, SigningKey

import aiohttp
from aiohttp import web, request
from aiohttp.abc import AbstractRouter

import lib.cose.cwt as cwt
from lib.cose import CoseKey
from lib.cbor.constants import Keys as CK
from lib.cose.constants import Key as Cose, Header
from lib.cose.cose import SignatureVerificationFailed
from lib.ace.rs import ResourceServer, NotAuthorizedException


class HTTPResourceServer(ResourceServer):

    def __init__(self, audience: str,
                 identity: SigningKey,
                 as_url: str,
                 as_public_key: VerifyingKey,
                 router: AbstractRouter,
                 client_id=None,
                 client_secret=None):

        super().__init__(audience, identity, as_url, as_public_key, client_id, client_secret)
        router.add_post('/authz-info', self.authz_info)
        router.add_post('/.well-known/edhoc', self.edhoc)

    def wrap(self, scope, handler):
        async def wrapped_handler(request):
            payload = await request.content.read()
            prot, unprot, cipher = loads(payload).value
            try:
                oscore_context = self.oscore_context(unprot, scope)
            except NotAuthorizedException:
                return web.Response(status=401, body=dumps({'error': 'not authorized'}))

            return await handler(request, payload, None, oscore_context)

        return wrapped_handler

    async def edhoc(self, request):
        message = await request.content.read()

        response = self.edhoc_server.on_receive(message)

        return web.Response(status=201, body=bytes(response))

    async def authz_info(self, request):
        # Extract access token
        access_token = await request.content.read()

        # introspect_payload = self.introspect(access_token)

        # Verify if valid CWT from AS
        try:
            decoded = cwt.decode(access_token, key=self.as_public_key)

        except SignatureVerificationFailed as err:
            return web.Response(status=401, body=dumps({'error': str(err)}))

        # Check if audience claim in token matches audience identifier of this resource server
        if decoded[CK.AUD] != self.audience:
            return web.Response(status=403, body=dumps({'error': 'Audience mismatch'}))

        # Extract PoP Key
        pop_key = CoseKey.from_cose(decoded[CK.CNF][Cose.COSE_KEY])

        # Store token and store by PoP key id
        self.token_cache.add_token(token=decoded, pop_key_id=pop_key.key_id)

        # Inform EDHOC Server about new key
        self.edhoc_server.add_peer_identity(pop_key.key_id, pop_key.key)

        return web.Response(status=201)
