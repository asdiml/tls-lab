"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets
from typing import Any
import cryptoimpl

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *

def client_version():
    cv = b'\x03\x03'
    return cv

def client_random():
    

def supported_ver_ext():

    ext_identifier = b'\x00\x2b'
    overall_ext_sz = b'\x00\x03' # Overall extension size = 3
    tls_ver_specifier_sz = b'\x02' # Size of TLS version specifier = 2
    tls_ver = b'\x03\x04' # Specifier for TLS version 1.3 => 03 04

    return ext_identifier + overall_ext_sz + tls_ver_specifier_sz + tls_ver

def sign_alg_ext():
    ext_identifier = b'\x00\x0d'
    overall_ext_sz = b'\x00\x02'
    data_ext_sz = b'\x00\x02'
    sign_alg_list = SignatureScheme.RSA_PSS_RSAE_SHA256.to_bytes(length=2, byteorder='big')

    return ext_identifier + overall_ext_sz + data_ext_sz + sign_alg_list

def supported_groups_ext():
    ext_identifier = b'\x00\x0a'
    overall_ext_sz = b'\x00\x02' 
    data_ext_sz = b'\x00\x02'
    group_identifiers = b'\x00\x1d'

    return ext_identifier + overall_ext_sz + data_ext_sz + group_identifiers  

def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the Ed25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """
    packet = []
    # TODO: construct the packet data

    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, b"".join(packet))

def key_share_ext(key_exchange_pubkey: bytes): 
    key_share_ext_identifier = b'\x00\x33'
    key_share_follow = b'\x00\x26'
    data_follow = b'\x00\x24'

def recv_server_hello(sock: client.TLSSocket) -> Any:
    # TODO: parse the server hello data
    pass

def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_ed25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    server_info = recv_server_hello(sock)
