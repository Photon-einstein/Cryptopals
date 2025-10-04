import json


def hex_to_int(h):
    return int(h, 16)


def int_to_hex(i, pad_bytes=None):
    h = format(i, "X")
    if pad_bytes:
        h = h.zfill(pad_bytes * 2)
    return h.upper()


def calculate_public_key(
    private_key_hex, N_hex, g_hex, is_server, k_hex=None, v_hex=None
):
    """
    Calculates the SRP public key (A or B).
    For the client: A = g^a mod N
    For the server: B = (k*v + g^b) mod N

    Args:
        private_key_hex (str): The private key (a or b) in hex.
        N_hex (str): The group prime N in hex.
        g_hex (str): The generator g in hex.
        is_server (bool): If True, computes B (server); if False, computes A (client).
        k_hex (str): Optional, k in hex (required for server).
        v_hex (str): Optional, v in hex (required for server).

    Returns:
        str: The public key (A or B) as an uppercase hex string.
    """
    N = hex_to_int(N_hex)
    g = hex_to_int(g_hex)
    private_key = hex_to_int(private_key_hex)
    pad_bytes = (N.bit_length() + 7) // 8

    if not is_server:
        # Client: A = g^a mod N
        A = pow(g, private_key, N)
        return int_to_hex(A, pad_bytes)
    else:
        if k_hex is None or v_hex is None:
            raise ValueError(
                "k_hex and v_hex are required for server public key calculation."
            )
        k = hex_to_int(k_hex)
        v = hex_to_int(v_hex)
        gb = pow(g, private_key, N)
        kv = (k * v) % N
        B = (kv + gb) % N
        return int_to_hex(B, pad_bytes)


if __name__ == "__main__":
    # Example RFC 5054 test vector values
    N_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
    g_hex = "2"
    a_hex = (
        "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393"  # RFC 5054 a
    )
    b_hex = (
        "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20"  # RFC 5054 b
    )
    k_hex = "7556AA045AEF2CDD07ABAF0F665C3E818913186F"  # RFC 5054 k
    v_hex = "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB"
    # RFC 5054 expected values
    A_expected = "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"
    B_expected = "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58"

    print("Testing calculatePublicKey as client (A = g^a mod N):")
    A_hex = calculate_public_key(a_hex, N_hex, g_hex, is_server=False)
    print("A =", A_hex)
    print("A_expected =", A_expected)
    print("Match:", A_hex == A_expected)
    print()

    print("Testing calculatePublicKey as server (B = (k*v + g^b) mod N):")
    B_hex = calculate_public_key(
        b_hex, N_hex, g_hex, is_server=True, k_hex=k_hex, v_hex=v_hex
    )
    print("B =", B_hex)
    print("B_expected =", B_expected)
    print("Match:", B_hex == B_expected)
