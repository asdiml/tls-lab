from .. import consts, util

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
