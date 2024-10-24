"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets
from typing import Any
import cryptoimpl

import random

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *
from tlsimpl.client_hello_extensions import *


def record_header():

    

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
    ciphers = b'\x01x\13x\02'
    return suite_count + ciphers

def compression_methods():
    return b'x\01\x00'

def create_client_hello_msg():
    client_msg = client_version() + client_random() + session_id() + cipher_suites() + compression_methods() 
    ext = supported_ver_ext() + sign_alg_ext() + supported_groups_ext() + key_share_ext()

    ext_len = len(ext).to_bytes(length=2, byteorder='big')

    return client_msg + ext_len

def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the Ed25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """
    packet = []
    # TODO: construct the packet data

    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, b"".join(packet))

def recv_server_hello(sock: client.TLSSocket) -> Any:
    # TODO: parse the server hello data
    pass

def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_ed25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    server_info = recv_server_hello(sock)
