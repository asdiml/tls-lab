from tlsimpl import cryptoimpl
from tlsimpl.cryptoimpl import *

def test_key_derivation():
    # same values as the one on https://tls13.xargs.org/#server-handshake-keys-calc
    transcript_hash = bytes.fromhex("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd")
    shared_secret = bytes.fromhex("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624")
    (client_params, server_params) = cryptoimpl.derive_aes_params(shared_secret, transcript_hash)
    assert client_params.key.hex() == "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69"
    assert client_params.initial_nonce == 0x4256d2e0e88babdd05eb2f27
    assert server_params.key.hex() == "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f"
    assert server_params.initial_nonce == 0x9563bc8b590f671f488d2da3
