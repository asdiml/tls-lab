"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets
from typing import Any

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *
from tlsimpl.client_hello import *
from tlsimpl.util import *


def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the X25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """
    client_hello_data = client_hello_without_ext() + client_hello_exts(key_exchange_pubkey)
    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, client_hello_data)


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

    data, rem = unpack_varlen(data) # Extract extension data
    assert rem == b''

    ext_list = []
    while data != b'':
        ext_type, ext_contents, data = unpack_extension(data)
        ext_list.append((ext_type, ext_contents))

        # Grab the server's public key for the HMAC-based Key Derivation Function
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
    (ty1, data1) = sock.recv_handshake_record() # Encrypted extensions
    (ty2, data2) = sock.recv_handshake_record() # Certificate 
    (ty3, data3) = sock.recv_handshake_record() # Certificate verify

    # TODO: Implement receipt of encrypted extensions and cerificate verification
    # For now, assert the types of the handshake records received
    assert ty1 == HandshakeType.ENCRYPTED_EXTENSIONS
    assert ty2 == HandshakeType.CERTIFICATE
    assert ty3 == HandshakeType.CERTIFICATE_VERIFY

    return


def finish_handshake(sock: client.TLSSocket, handshake_secret: bytes) -> None:
    """
    Receives the server finish, sends the client finish, and derives the application keys.
    """
    # Verify server finish
    cur_transcript_hash = sock.transcript_hash.digest()
    server_finish_own = cryptoimpl.compute_finish(sock.server_params.original_secret, cur_transcript_hash)
    (server_finish_ty, server_finish_data) = sock.recv_handshake_record()
    
    assert server_finish_ty == HandshakeType.FINISHED, "Invalid handshake type for SERVER FINISH"
    if server_finish_data != server_finish_own:
        raise Exception("Server finish verification failed: Data mismatch")

    # Key derivation for application keys
    (client_params, server_params) = (
        cryptoimpl.derive_application_params(handshake_secret, sock.transcript_hash.digest())
    )

    # Send client finish
    cur_transcript_hash = sock.transcript_hash.digest()
    client_finish = cryptoimpl.compute_finish(sock.client_params.original_secret, cur_transcript_hash)
    sock.send_handshake_record(HandshakeType.FINISHED, client_finish)

    # Set the socket params to the application key params
    sock.client_params = client_params # Set sock.client_params to the application key params
    sock.server_params = server_params # Set sock.server_params to the application key params


def recv_new_session_tickets(sock: client.TLSSocket) -> None:
    (ty1, data1) = sock.recv_handshake_record() # New session ticket 1
    (ty2, data2) = sock.recv_handshake_record() # New session ticket 2 

    # For this simplified implementation, we are not caching the session tokens for reuse later
    # Instead, we assert that the record types are HandShakeType.NEW_SESSION_TICKET
    assert ty1 == HandshakeType.NEW_SESSION_TICKET
    assert ty2 == HandshakeType.NEW_SESSION_TICKET


def perform_handshake(sock: client.TLSSocket) -> None:
    # Generate key pair for key derivation
    key_exchange_keypair = cryptoimpl.generate_x25519_keypair()

    # Send client hello and receive server hello
    send_client_hello(sock, key_exchange_keypair[1])
    peer_pubkey = recv_server_hello(sock)

    # Key derivation for handshake keys
    shared_secret = cryptoimpl.derive_shared_x25519_key(
        key_exchange_keypair[0], peer_pubkey
    )
    (handshake_secret, client_params, server_params) = (
        cryptoimpl.derive_handshake_params(shared_secret, sock.transcript_hash.digest())
    )
    sock.client_params = client_params # Set sock.client_params to the handshake key params
    sock.server_params = server_params # Set sock.server_params to the handshake key params

    # Handle the server's certificates, and finish the handshake
    recv_server_info(sock)
    finish_handshake(sock, handshake_secret)


def interact_with_server(sock: client.TLSSocket) -> None:
    # Receive new session tickets (we do not use store them in this simplified implementation)
    recv_new_session_tickets(sock)

    # Wait for all the handshake trace data from openssl s_server to come through
    import time
    time.sleep(1)

    while True:
        # Prompt user for data to send to the openssl s_server
        print("\nTLS v1.3 connection established!\nSend something to the openssl server > ", end="")
        user_data = input()
        sock.send_record(RecordType.APPLICATION_DATA, user_data.encode())
        print() # For a newline

        # Wait for the "Received Record" trace data
        time.sleep(1.5)

        # Server's turn to send data
        print("\n\nNow you are the server, pls reply > ", end="")
        (ty, data) = sock.recv_record()
        print() # For a newline
        assert ty == RecordType.APPLICATION_DATA
        print(f"Data received from the server: {data}")

        # Wait for the "Sent Record" trace data
        time.sleep(1.5)