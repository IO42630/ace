import aiocoap
from aiocoap import resource
from cbor2 import dumps, loads
from ecdsa import SigningKey, VerifyingKey

import ace.cose.cwt as cwt
from ace.rs import NotAuthorizedException, ResourceServer
from ace.cbor.constants import Keys as CK
from ace.cose import CoseKey
from ace.cose.constants import Key as Cose
from ace.cose.constants import Header
from ace.cose.cose import SignatureVerificationFailed


class AuthzInfoResource(resource.Resource):

    def __init__(self, resource_server):
        super().__init__()
        self.resource_server = resource_server

    async def render_post(self, request):
        access_token = request.payload

        # introspect_payload = self.introspect(access_token)

        # Verify if valid CWT from AS
        try:
            decoded = cwt.decode(access_token, key=self.resource_server.as_public_key)

        except SignatureVerificationFailed as err:
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED)

        # Check if audience claim in token matches audience identifier of this resource server
        if decoded[CK.AUD] != self.resource_server.audience:
            return aiocoap.Message(code=aiocoap.FORBIDDEN)

        # Extract PoP Key
        pop_key = CoseKey.from_cose(decoded[CK.CNF][Cose.COSE_KEY])

        # Store token and store by PoP key id
        self.resource_server.token_cache.add_token(token=decoded, pop_key_id=pop_key.key_id)

        # Inform EDHOC Server about new key
        self.resource_server.edhoc_server.add_peer_identity(pop_key.key_id, pop_key.key)
        
        return aiocoap.Message(code=aiocoap.CREATED)


class EdhocResource(resource.Resource):

    def __init__(self, resource_server):
        super().__init__()
        self.resource_server = resource_server

    async def render_post(self, request):
        message = request.payload
        response = self.resource_server.edhoc_server.on_receive(message)
        return aiocoap.Message(code=aiocoap.CREATED, payload=bytes(response))


class CoAPResourceServer(ResourceServer):

    def __init__(self, audience: str,
                 identity: SigningKey,
                 as_url: str,
                 as_public_key: VerifyingKey,
                 site,
                 client_id=None,
                 client_secret=None):

        super().__init__(audience, identity, as_url, as_public_key, client_id, client_secret)
        self.site = site
        self.site.add_resource(('authz-info',), AuthzInfoResource(self))
        self.site.add_resource(('.well-known', 'edhoc'), EdhocResource(self))

    async def edhoc(self, request):
        response = self.edhoc_server.on_receive(request.payload)

        return aiocoap.Message(payload=response)

    async def authz_info(self, request):
        access_token = request.payload
        # Verify if valid CWT from AS
        try:
            decoded = cwt.decode(access_token, key=self.as_public_key)
        except SignatureVerificationFailed as err:
            return aiocoap.Message(code=aiocoap.UNAUTHORIZED)

        # Check if audience claim in token matches audience identifier of this resource server
        if decoded[CK.AUD] != self.audience:
            return web.Response(status=403, body=dumps({'error': 'Audience mismatch'}))

        # Extract PoP Key
        pop_key = CoseKey.from_cose(decoded[CK.CNF][Cose.COSE_KEY])

        # Store token and store by PoP key id
        self.token_cache.add_token(token=decoded, pop_key_id=pop_key.key_id)

        # Inform EDHOC Server about new key
        self.edhoc_server.add_peer_identity(pop_key.key_id, pop_key.key)

        return aiocoap.Message(code=aiocoap.CREATED)
