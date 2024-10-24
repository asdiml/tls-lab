from tlsimpl.consts import *

def supported_ver_ext():
    ext_identifier = ExtensionType.SUPPORTED_VERSIONS.to_bytes(length=2, byteorder='big')
    overall_ext_sz = b'\x00\x03' # Overall extension size = 3
    ext_data_sz = b'\x02' # Size of TLS version specifier = 2
    tls_ver = b'\x03\x04' # Specifier for TLS version 1.3 => 03 04

    return ext_identifier + overall_ext_sz + ext_data_sz + tls_ver

def sign_alg_ext():
    ext_identifier = ExtensionType.SIGNATURE_ALGORITHMS.to_bytes(length=2, byteorder='big')
    overall_ext_sz = b'\x00\x04'
    ext_data_sz = b'\x00\x02'
    sign_alg_list = SignatureScheme.ED25519.to_bytes(length=2, byteorder='big')

    return ext_identifier + overall_ext_sz + ext_data_sz + sign_alg_list

def supported_groups_ext():
    ext_identifier = ExtensionType.SUPPORTED_GROUPS.to_bytes(length=2, byteorder='big')
    overall_ext_sz = b'\x00\x04' 
    ext_data_sz = b'\x00\x02'
    group_identifiers = b'\x00\x1d'

    return ext_identifier + overall_ext_sz + ext_data_sz + group_identifiers

def key_share_ext(key_exchange_pubkey: bytes): 
    ext_identifier = ExtensionType.KEY_SHARE.to_bytes(length=2, byteorder='big')
    overall_ext_sz = b'\x00\x26'
    ext_data_sz = b'\x00\x24'
    elliptic_curve_identifier = b'\x00\x1d'
    key_len = b'\x00\x20'

    return ext_identifier + overall_ext_sz + ext_data_sz + elliptic_curve_identifier + key_len + key_exchange_pubkey
    