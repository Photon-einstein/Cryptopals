import hashlib


def hex_to_bytes(hexstr):
    return bytes.fromhex(hexstr)


def calculate_u(hash_name, A_hex, B_hex):
    # Convert hex to bytes
    A_bytes = hex_to_bytes(A_hex)
    B_bytes = hex_to_bytes(B_hex)
    # Concatenate A || B
    input_bytes = A_bytes + B_bytes
    # Select hash function
    hash_name = hash_name.lower().replace("-", "")
    if hash_name == "sha1":
        h = hashlib.sha1()
    elif hash_name == "sha256":
        h = hashlib.sha256()
    elif hash_name == "sha384":
        h = hashlib.sha384()
    elif hash_name == "sha512":
        h = hashlib.sha512()
    else:
        raise ValueError("Unsupported hash: " + hash_name)
    h.update(input_bytes)
    return h.hexdigest().upper()


if __name__ == "__main__":
    A_hex = "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"
    B_hex = "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58"
    hash_name = "SHA-1"
    u = calculate_u(hash_name, A_hex, B_hex)
    print(f"u = {u}")
    u_hex_expected = "CE38B9593487DA98554ED47D70A7AE5F462EF019"  # RFC 5054"
    print(f"\nu_expected = {u_hex_expected}\n")
