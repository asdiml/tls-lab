"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets
from typing import Any

import random

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *
from tlsimpl.client_hello.extensions import *

def record_header(msg):
    ver = b'x\03\x01'
    msg_len = len(msg).to_bytes(length=2, byteorder='big')
    return 'x\16' + ver + msg_len + msg
    
def client_version():
    cv = b'\x03\x03'
    return cv  

def client_random():
    client_rand = random.randbytes(32)
    return client_rand

def session_id():
    sess_id = b'\x00'
    return sess_id

def cipher_suites():
    suite_count = b'\x00\x02'
    ciphers = b'\x13\x02'

    return suite_count + ciphers

def compression_methods():
    return b'\x01\x00'

def create_client_hello_msg(key_exchange_pubkey: bytes):
    client_msg = client_version() + client_random() + session_id() + cipher_suites() + compression_methods() 
    ext = supported_ver_ext() + sign_alg_ext() + supported_grps_ext() + key_share_ext(key_exchange_pubkey)

    ext_len = len(ext).to_bytes(length=2, byteorder='big')

    print("Len", ext_len)
    print("Ext", ext)

    return client_msg + ext_len + ext

def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the X25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """
    packet = create_client_hello_msg(key_exchange_pubkey)
    print(f"Client hello packet: {packet}")

    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, packet)

def recv_server_hello(sock: client.TLSSocket) -> bytes:
    """
    Parses the TLS v1.3 server hello.

    Returns the pubkey of the server.

    Specified in RFC8446 section 4.1.3.
    """
    (ty, data) = sock.recv_handshake_record()
    assert ty == HandshakeType.SERVER_HELLO
    # TODO: parse server hello and find server pubkey
    peer_pubkey = b"???"
    return peer_pubkey

    return "Hello"

def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_x25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    peer_pubkey = recv_server_hello(sock)
    shared_secret = cryptoimpl.derive_shared_x25519_key(
        key_exchange_keypair[0], peer_pubkey
    )
    transcript_hash = sock.transcript_hash.digest()
    (sock.client_params, sock.server_params) = cryptoimpl.derive_aes_params(
        shared_secret, transcript_hash
    )
    # receive an encrypted handshake record to verify decryption works
    print("got record:", sock.recv_handshake_record())
