import requests

from ecdsa import SigningKey, VerifyingKey, NIST256p
from lib.edhoc import Client as EdhocClient


class AceSession:

    session_id = 0

    def __init__(self, session_id, private_pop_key, public_pop_key, pop_key_id: bytes):
        self.session_id = session_id
        self.private_pop_key = private_pop_key
        self.public_pop_key = public_pop_key
        self.pop_key_id = pop_key_id
        self.token = None
        self.rs_url = None
        self.edhoc_client = EdhocClient(self.private_pop_key,
                                   None,
                                   kid=self.pop_key_id)
        self.oscore_context = None

    # @property
    # def oscore_context(self):
    #     return self.edhoc_client.session.oscore_context

    @property
    def rs_public_key(self):
        return self.edhoc_client.server_id

    @rs_public_key.setter
    def rs_public_key(self, value):
        self.edhoc_client.server_id = value

    @classmethod
    def create(cls, key_id: bytes):
        (prv_key, pub_key) = AceSession.generate_session_key()

        session_id = AceSession.session_id
        AceSession.session_id += 1

        return AceSession(session_id=session_id,
                          private_pop_key=prv_key,
                          public_pop_key=pub_key,
                          pop_key_id=key_id)

    @staticmethod
    def generate_session_key():
        """
        Generates an asymmetric session key
        :return: (private_key, public_key) pair
        """

        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.get_verifying_key()

        return private_key, public_key
