from aiohttp import web, request
from aiohttp.abc import AbstractRouter
from cbor2 import dumps, loads
from ecdsa import VerifyingKey, SigningKey

import lib.cose.cwt as cwt
from lib.cbor.constants import Keys as CK
from lib.cose.constants import Key as Cose, Header
from lib.cose.cose import SignatureVerificationFailed
from lib.cose import CoseKey
from lib.edhoc import Server as EdhocServer
from .token_cache import TokenCache


class AudienceMismatchError(Exception):
    pass


class IntrospectionFailedError(Exception):
    pass


class IntrospectNotActiveError(Exception):
    pass


class NotAuthorizedException(Exception):
    pass


class ResourceServer(object):

    def __init__(self, audience: str,
                 identity: SigningKey,
                 as_url: str,
                 as_public_key: VerifyingKey,
                 client_id=None,
                 client_secret=None):

        self.audience = audience
        self.identity = identity
        self.as_url = as_url
        self.as_public_key = as_public_key

        self.client_secret = client_secret
        self.client_id = client_id
        self.token_cache = TokenCache()

        self.edhoc_server = EdhocServer(self.identity)

    def oscore_context(self, unprotected_header, scope):
        kid = unprotected_header[Header.KID]

        # Retrieve token for recipient
        pop_key_id = self.edhoc_server.pop_key_id_for_recipient(rid=kid)
        token = self.token_cache.get_token(pop_key_id=pop_key_id)

        # Verify scope
        authorized_scopes = token[CK.SCOPE].split(",")
        if scope not in authorized_scopes:
            raise NotAuthorizedException()

        return self.edhoc_server.oscore_context_for_recipient(kid)

    async def edhoc(self, request):
        raise NotImplementedError

    async def authz_info(self, request):
        raise NotImplementedError

    async def introspect(self, token: str):
        """
        POST token to AS for introspection using RS as a client of the AS
        :param token: The token to be introspected (not self-contained)
        """

        cose = {
            CK.TOKEN: token,
            CK.TOKEN_TYPE_HINT: 'pop',
            CK.CLIENT_ID: self.client_id,
            CK.CLIENT_SECRET: self.client_secret
        }

        async with request('POST', f'{self.as_url}/introspect', data=dumps(cose)) as resp:
            if resp.status != 201:
                raise IntrospectionFailedError()
            response_payload = loads(await resp.read())
        """ ACE p. 61
        Response-Payload:
        {
            "active" : true,
            "aud" : "lockOfDoor4711",
            "scope" : "open, close",
            "iat" : 1311280970,
            "cnf" : {
                "kid" : b64’JDLUhTMjU2IiwiY3R5Ijoi ...’
            }
        }
        """

        if resp.status != 201:
            raise IntrospectionFailedError()

        if not response_payload[CK.ACTIVE]:
            raise IntrospectNotActiveError()

        if response_payload[CK.AUD] != self.audience:
            raise AudienceMismatchError()

        return response_payload

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
