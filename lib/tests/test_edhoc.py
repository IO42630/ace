import unittest
import hashlib
from ecdsa import SigningKey, NIST256p, NIST384p
from lib.edhoc import Client, Server
from lib.edhoc.util import ecdsa_key_to_cose, ecdsa_cose_to_key


class TestEdhoc(unittest.TestCase):

    def setUp(self):
        client_sk = SigningKey.generate(curve=NIST256p)
        server_sk = SigningKey.generate(curve=NIST256p)

        client_id = client_sk.get_verifying_key()
        server_id = server_sk.get_verifying_key()

        self.client = Client(client_sk, server_id)
        self.server = Server(server_sk, client_id)

    def test_signature(self):
        sk = SigningKey.generate(curve=NIST384p)
        vk = sk.get_verifying_key()

        encoded = ecdsa_key_to_cose(vk)

        data = b"this is some data I'd like to sign"
        signature = sk.sign(data, hashfunc=hashlib.sha256)

        decoded = ecdsa_cose_to_key(encoded)
        assert(decoded.verify(signature, data, hashfunc=hashlib.sha256))

    def test_context(self):
        send = lambda message: (
            self.server.on_receive(message.serialize()).serialize()
        )

        self.client.initiate_edhoc(send)
        self.client.continue_edhoc(send)

        client_ctx = self.client.oscore_context
        server_ctx = self.server.oscore_context
        assert(client_ctx == server_ctx)

    def test_encrypt(self):
        send = lambda message: (
            self.server.on_receive(message.serialize()).serialize()
        )

        self.client.initiate_edhoc(send)
        self.client.continue_edhoc(send)

        server_plaintext = b"hello from server"
        assert self.client.decrypt(self.server.encrypt(server_plaintext)) == server_plaintext

        client_plaintext = b"hello from client"
        assert self.server.decrypt(self.client.encrypt(client_plaintext)) == client_plaintext

if __name__ == '__main__':
    unittest.main()
