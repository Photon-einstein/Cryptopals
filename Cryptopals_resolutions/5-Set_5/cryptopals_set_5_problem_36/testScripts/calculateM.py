import hashlib

def hex_to_bytes(hexstr):
    return bytes.fromhex(hexstr)

def hash_bytes(hash_name, data):
    hash_name = hash_name.replace("-", "").lower()
    if hash_name == "sha256":
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
    hu = hash_bytes(hash_name, username.encode('utf-8'))
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
    hash_name = "SHA-256"
    N_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E8607261877519"
    g_hex = "02"
    username = "alice"
    salt_hex = "BEB25379D1A8581EB5A727673A2441EE"
    A_hex = "61D5E490F6F1"
    B_hex = "BD0C615B8E"
    K_hex = "B0DC82BABCF30674AE450C0287745E4B"

    # Print M
    print(calculateM(hash_name, N_hex, g_hex, username, salt_hex, A_hex, B_hex, K_hex))