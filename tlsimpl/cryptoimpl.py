"""
The cryptography implementations for TLS.
"""

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tlsimpl import util


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """
    Generates an X25519 (private, public) keypair.
    """
    priv_key = X25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    return (priv_key.private_bytes_raw(), pub_key.public_bytes_raw())


def derive_shared_x25519_key(privkey: bytes, peer_pubkey: bytes) -> bytes:
    """
    Derive a shared key from private key and peer's public key.
    """

    priv = X25519PrivateKey.from_private_bytes(privkey)
    pub = X25519PublicKey.from_public_bytes(peer_pubkey)
    return priv.exchange(pub)


def sha384_hkdf_extract(salt: bytes, data: bytes) -> bytes:
    """
    Performs a SHA384 HKDF extraction.
    """
    return hmac.digest(salt, data, hashlib.sha384)


def labeled_sha384_hkdf(
    secret: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    """
    Performs a TLS 1.3 labeled SHA384 HKDF key derivation.

    Specified in RFC8446 section 7.1.
    """
    constructed_label = (
        util.pack(length, 2)
        + util.pack_varlen(b"tls13 " + label, 1)
        + util.pack_varlen(context, 1)
    )
    return HKDFExpand(
        algorithm=hashes.SHA384(), length=length, info=constructed_label
    ).derive(secret)


@dataclass
class AESParams:
    """
    AES-GCM parameters using an incrementing sequence number to be XORed with initial nonce.
    """

    key: bytes
    initial_nonce: int
    seq_num: int = 0

    def get_nonce(self) -> bytes:
        """
        Gets a new per-record nonce and increments the sequence number.

        Specified in RFC8446 section 5.3.
        """
        nonce = b"???"
        # TODO: derive the nonce
        return nonce

    def encrypt(self, msg: bytes, aad: bytes | None) -> bytes:
        """
        Encrypts a message with AES-GCM with optional AAD.
        """
        return AESGCM(self.key).encrypt(self.get_nonce(), msg, aad)

    def decrypt(self, msg: bytes, aad: bytes | None) -> bytes:
        """
        Decrypts a message with AES-GCM with optional AAD.
        """
        return AESGCM(self.key).decrypt(self.get_nonce(), msg, aad)


def derive_aes_params(
    shared_secret: bytes, transcript_hash: bytes
) -> tuple[AESParams, AESParams]:
    """
    Given the shared secret and transcript hash, return a (client, server) tuple of AES parameters.
    """
    # TODO: derive client/server key/iv
    client_key = b"???"
    client_iv = b"???"
    server_key = b"???"
    server_iv = b"???"
    client_params = AESParams(client_key, util.unpack(client_iv))
    server_params = AESParams(server_key, util.unpack(server_iv))
    return (client_params, server_params)
