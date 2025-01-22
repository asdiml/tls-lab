from tlsimpl import consts, util
import random

def client_hello_without_ext():
    client_version = b'\x03\x03' # TLS v1.2 (the RFC describes how TLS v1.3 packets must be disguised as TLS v1.2 packets, with the v1.3 being specified in extensions)
    client_rand = random.randbytes(32)
    session_id = b'\x00' # No longer needed - we are putting a null byte here to indicate this
    cipher_suites = util.pack_varlen(util.pack(consts.CipherSuite.TLS_AES_256_GCM_SHA384, width=2)) # Only accept the TLS_AES_256_GCM_SHA384 cipher suite
    compression_methods = util.pack_varlen(b'\x00', len_width=1) # Compression is not allowed in TLS v1.3
    return client_version + client_rand + session_id + cipher_suites + compression_methods

def client_hello_exts(key_exchange_pubkey: bytes):
    ext_data = supported_ver_ext() + sign_alg_ext() + supported_grps_ext() + key_share_ext(key_exchange_pubkey)
    return util.pack_varlen(ext_data, len_width=2)

def supported_ver_ext():    
    tls_ver = b'\x03\x04' # Specifier for TLS version 1.3 => 03 04
    tls_ver_data_packed = util.pack_varlen(tls_ver, len_width=1)

    return util.pack_extension(consts.ExtensionType.SUPPORTED_VERSIONS, tls_ver_data_packed)

def sign_alg_ext():
    sign_alg_list = b''.join([
        util.pack(consts.SignatureScheme.RSA_PSS_RSAE_SHA384, 2), # Add more as required
    ])
    sign_alg_list_data_packed = util.pack_varlen(sign_alg_list, len_width=2)

    return util.pack_extension(consts.ExtensionType.SIGNATURE_ALGORITHMS, sign_alg_list_data_packed)

def supported_grps_ext():
    supported_grps_list = b''.join([
        util.pack(consts.NamedGroup.X25519, 2) # Add more as required
    ])
    supported_grps_list_data_packed = util.pack_varlen(supported_grps_list, len_width=2)

    return util.pack_extension(consts.ExtensionType.SUPPORTED_GROUPS, supported_grps_list_data_packed)

def key_share_ext(key_exchange_pubkey: bytes): 
    pubkey_data_packed = util.pack_varlen(key_exchange_pubkey, len_width=2)
    elptc_curve_id = util.pack(consts.NamedGroup.X25519, 2) # Change if the elliptic curve used is different
    key_share_data_packed = util.pack_varlen(elptc_curve_id + pubkey_data_packed, len_width=2)

    return util.pack_extension(consts.ExtensionType.KEY_SHARE, key_share_data_packed)
