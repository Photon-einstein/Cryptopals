import hashlib


def calculateK(hash_name, S_hex):
    S_bytes = bytes.fromhex(S_hex)
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
    h.update(S_bytes)
    return h.hexdigest().upper()


if __name__ == "__main__":
    # Example S value (hex string)
    S_hex = "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"
    hash_algorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]
    for hash_name in hash_algorithms:
        K_hex = calculateK(hash_name, S_hex)
        print(f"{hash_name}: {K_hex}")
