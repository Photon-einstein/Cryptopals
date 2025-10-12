import hashlib

from calculateK import calculateK


def hex_to_bytes(hexstr):
    return bytes.fromhex(hexstr)


def hash_bytes(hash_name, data):
    hash_name = hash_name.replace("-", "").lower()
    if hash_name == "sha1":
        h = hashlib.sha1()
    elif hash_name == "sha256":
        h = hashlib.sha256()
    elif hash_name == "sha384":
        h = hashlib.sha384()
    elif hash_name == "sha512":
        h = hashlib.sha512()
    else:
        raise ValueError(f"Unsupported hash: {hash_name}")
    h.update(data)
    return h.digest()


def calculateM(hash_name, N_hex, g_hex, username, salt_hex, A_hex, B_hex, K_hex):
    # H(N)
    N_bytes = hex_to_bytes(N_hex)
    hN = hash_bytes(hash_name, N_bytes)
    # H(g)
    g_bytes = hex_to_bytes(g_hex)
    hg = hash_bytes(hash_name, g_bytes)
    # H(U)
    hu = hash_bytes(hash_name, username.encode("utf-8"))
    # H(N) XOR H(g)
    hn_xor_hg = bytes(a ^ b for a, b in zip(hN, hg))
    # salt, A, B, K as bytes
    salt_bytes = hex_to_bytes(salt_hex)
    A_bytes = hex_to_bytes(A_hex)
    B_bytes = hex_to_bytes(B_hex)
    K_bytes = hex_to_bytes(K_hex)
    # Concatenate all parts
    m_input = hn_xor_hg + hu + salt_bytes + A_bytes + B_bytes + K_bytes
    # Hash the concatenated value
    m = hash_bytes(hash_name, m_input)
    return m.hex().upper()


if __name__ == "__main__":
    # Test values
    N_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
    g = 2
    g_hex = format(g, "02X")  # Convert integer g to hex string (uppercase, no '0x')
    username = "alice"
    salt_hex = "BEB25379D1A8581EB5A727673A2441EE"
    A_hex = "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"
    B_hex = "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58"
    S_hex = "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"

    hash_algorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]
    for hash_name in hash_algorithms:
        M = calculateM(
            hash_name,
            N_hex,
            g_hex,
            username,
            salt_hex,
            A_hex,
            B_hex,
            calculateK(hash_name, S_hex),
        )
        print(f"{hash_name}: {M}")
