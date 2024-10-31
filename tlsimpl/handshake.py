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
from tlsimpl.util import *

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

def extract_byte_substr(n, data: bytes) -> tuple[bytes, bytes]:
    return (data[:n], data[n:])

def recv_server_hello(sock: client.TLSSocket) -> bytes:
    """
    Parses the TLS v1.3 server hello.

    Returns the pubkey of the server.

    Specified in RFC8446 section 4.1.3.
    """
    (ty, data) = sock.recv_handshake_record()
    assert ty == HandshakeType.SERVER_HELLO

    (serv_tls_ver, data) = extract_byte_substr(2, data)
    (serv_random, data) = extract_byte_substr(32, data)
    (sess_id, data)= unpack_varlen(data, len_width=1)
    (cipher_suite, data) = extract_byte_substr(2, data)
    (compress, data) = extract_byte_substr(1, data)
    cipher_suite = consts.CipherSuite(unpack(cipher_suite))

    print(f"{serv_tls_ver=}")
    print(f"{serv_random=}")
    print(f"{sess_id=}")
    print(f"{cipher_suite=}")
    print(f"{compress=}")

    data, rem = unpack_varlen(data) # Extract extension data
    assert rem == b''

    ext_list = []
    while data != b'':
        ext_type, ext_contents, data = unpack_extension(data)
        ext_list.append((ext_type, ext_contents))

        if ext_type == consts.ExtensionType.KEY_SHARE:
            if consts.NamedGroup(unpack(ext_contents[:2])) == consts.NamedGroup.X25519:
                peer_pubkey, _ = unpack_varlen(ext_contents[2:])

    print(f"{ext_list=}")
    return peer_pubkey

def recv_server_info(sock: client.TLSSocket) -> None:
    """
    Receives the server's encrypted extensions, certificate, and certificate verification.

    Also verifies the certificate's validity.
    """
    # TODO: implement


def finish_handshake(sock: client.TLSSocket, handshake_secret: bytes) -> None:
    """
    Receives the server finish, sends the client finish, and derives the application keys.

    Takes in the shared secret from key exchange.
    """
    # TODO: implement


def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_x25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    peer_pubkey = recv_server_hello(sock)
    shared_secret = cryptoimpl.derive_shared_x25519_key(
        key_exchange_keypair[0], peer_pubkey
    )
    transcript_hash = sock.transcript_hash.digest()
    (handshake_secret, sock.client_params, sock.server_params) = (
        cryptoimpl.derive_handshake_params(shared_secret, transcript_hash)
    )
    recv_server_info(sock)
    finish_handshake(sock, handshake_secret)
    # receive an encrypted record to make sure everything works
    print(sock.recv_record())
