from cbor2 import dumps, loads
from cbor2.encoder import encode_array

from lib.cose import Signature1Message, Encrypt0Message
from lib.cose.cose import Header, Algorithm
from lib.edhoc.util import ecdh_key_to_cose, ecdh_cose_to_key

EDHOC_MSG_1 = 1
EDHOC_MSG_2 = 2
EDHOC_MSG_3 = 3


class EdhocMessage():

    _tag = None

    def __init__(self, bytes_object: bytes):
        self._bytes_object = bytes_object

    @property
    def tag(self):
        return self._tag

    @property
    def _data(self):
        return NotImplementedError

    def __getitem__(self, index):
        return self._data[index]

    def __len__(self):
        return len(self._data)

    def __bytes__(self):
        if self._bytes_object is not None:
            return self._bytes_object
        return dumps(self, default=encode_array)

    def __add__(self, other):
        return bytes(self)+other

    def __radd__(self, other):
        return other+bytes(self)

    @classmethod
    def from_bytes(cls, bytes_object):
        return NotImplementedError


class Message1(EdhocMessage):

    _tag = EDHOC_MSG_1

    def __init__(self, session_id: bytes, nonce: bytes, ephemeral_key, bytes_object: bytes=None):
        super().__init__(bytes_object)
        self.session_id = session_id
        self.nonce = nonce
        self.ephemeral_key = ephemeral_key

    @property
    def _data(self):
        return (self.tag,
                self.session_id,
                self.nonce,
                ecdh_key_to_cose(self.ephemeral_key, encode=True))

    @classmethod
    def from_bytes(cls, bytes_object):
        (tag, session_id, nonce, cose_key) = loads(bytes_object)

        if tag != EDHOC_MSG_1:
            raise ValueError("Not a MSG1 type")

        msg1 = Message1(session_id=session_id,
                        nonce=nonce,
                        ephemeral_key=ecdh_cose_to_key(cose_key))
        assert (dumps(msg1, default=encode_array) == bytes_object)
        return msg1


class Message2(EdhocMessage):

    _tag = EDHOC_MSG_2

    def __init__(self, session_id: bytes, peer_session_id: bytes, peer_nonce: bytes, peer_ephemeral_key, bytes_object:bytes=None):
        super().__init__(bytes_object)
        self.session_id = session_id
        self.peer_session_id = peer_session_id
        self.peer_nonce = peer_nonce
        self.peer_key = peer_ephemeral_key

        self._aad_2 = None
        self._cose_sig_v = None
        self._cose_enc_2 = None

    def sign(self, key, aad: bytes):
        self._aad_2 = aad
        self._cose_sig_v = self.cose_sig_v(key)

    def encrypt(self, key, iv):
        self._cose_enc_2 = self.cose_enc_2(key, iv)
        pass

    @property
    def _data(self):
        return (*self.data_2, self._cose_enc_2)

    @property
    def data_2(self):
        return (self.tag,
                self.session_id,
                self.peer_session_id,
                self.peer_nonce,
                ecdh_key_to_cose(self.peer_key, kid=b'abcd', encode=True))

    def aad_2(self, hashfunc, message_1: bytes):
        return hashfunc(message_1 + dumps(self.data_2))

    def cose_enc_2(self, key, iv):
        protected_header = dumps({Header.ALG: Algorithm.AES_CCM_64_64_128})
        unprotected_header = { Header.IV: iv }

        return Encrypt0Message(
            plaintext=self._cose_sig_v,
            protected_header=protected_header,
            unprotected_header=unprotected_header,
            external_aad=self._aad_2
        ).serialize(iv, key)

    def cose_sig_v(self, key):
        protected = dumps({ Header.ALG: Algorithm.ES256 })
        unprotected = { Header.KID: b'AsymmetricECDSA256' }

        return Signature1Message(
            payload=b'',
            external_aad=self._aad_2,
            protected_header=protected,
            unprotected_header=dumps(unprotected)
        ).serialize_signed(key)

    @classmethod
    def from_bytes(cls, bytes_object):
        (tag, session_id, peer_session_id, peer_nonce, cose_key, cose_enc_2) = loads(bytes_object)

        if tag != EDHOC_MSG_2:
            raise ValueError("Not a MSG2 type")

        return Message2(session_id=session_id,
                        peer_session_id=peer_session_id,
                        peer_nonce=peer_nonce,
                        peer_ephemeral_key=cose_key)


class Message3(EdhocMessage):

    _tag = EDHOC_MSG_3

    def __init__(self, peer_session_id, bytes_object: bytes=None):
        super().__init__(bytes_object)
        self.peer_session_id = peer_session_id

        self._aad_3 = None
        self._cose_sig_u = None
        self._cose_enc_3 = None

    def sign(self, key, kid: bytes, aad: bytes):
        self._aad_3 = aad
        self._cose_sig_u = self.cose_sig_u(key, kid)

    def encrypt(self, key, iv):
        self._cose_enc_3 = self.cose_enc_3(key, iv)

    @property
    def _data(self):
        return (*self.data_3, self._cose_enc_3)

    @property
    def data_3(self):
        return (self.tag, self.peer_session_id)

    def aad_3(self, hashfunc, message1: bytes, message2: bytes):
        return hashfunc(hashfunc(message1 + message2) + dumps(self.data_3))

    def cose_enc_3(self, key, iv):
        protected_header = dumps({Header.ALG: Algorithm.AES_CCM_64_64_128})
        unprotected_header = {Header.IV: iv}

        return Encrypt0Message(
            plaintext=self._cose_sig_u,
            protected_header=protected_header,
            unprotected_header=unprotected_header,
            external_aad=self._aad_3
        ).serialize(iv, key)

    def cose_sig_u(self, key, kid: bytes):
        protected = dumps({ Header.ALG: Algorithm.ES256 })
        unprotected = { Header.KID: kid }

        return Signature1Message(
            payload=b'',
            external_aad=self._aad_3,
            protected_header=protected,
            unprotected_header=dumps(unprotected)
        ).serialize_signed(key)


class MessageOk(EdhocMessage):

    def __init__(self):
        super().__init__(dumps(["OK"]))


class MessageError:

    def __init__(self):
        super().__init__(dumps(["Error"]))