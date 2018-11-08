from cbor2 import dumps, loads
from ecdsa import VerifyingKey, SigningKey

import ace.cose.cwt as cwt
from ace.cbor.constants import Keys as CK
from ace.cose.constants import Key as Cose, Header
from ace.cose.cose import SignatureVerificationFailed
from ace.cose import CoseKey
from ace.edhoc import Server as EdhocServer
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
        from aiohttp import request

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
