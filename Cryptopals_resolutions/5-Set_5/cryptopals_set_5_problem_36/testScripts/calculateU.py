"""
calculateU.py

Utilities to compute the SRP scrambling parameter u as defined in RFC 5054.

This module provides:
- hex_to_bytes(hexstr, pad_bytes=None) -> bytes
    Convert a hexadecimal string to raw bytes and optionally left-pad the result
    with zero bytes to reach a specified byte length.

- calculate_u(hash_name, A_hex, B_hex, N_hex) -> str
    Compute u = H(PAD(A) || PAD(B)) where PAD(x) denotes left-padding x to the
    byte-length of N. The function selects the requested hash algorithm
    (SHA-1, SHA-256, SHA-384, SHA-512) and returns the digest as an uppercase
    hexadecimal string.

Notes:
- All hex inputs are expected without a "0x" prefix.
- The returned hex string is uppercase for consistency with other tools.
"""

import hashlib


def hex_to_bytes(hexstr, pad_bytes=None):
    """
    Convert a hexadecimal string to bytes and optionally left-pad to pad_bytes.

    Parameters:
    - hexstr (str): Hexadecimal string (upper/lower case allowed, no "0x" prefix).
    - pad_bytes (int | None): If provided and the resulting bytes length is less
      than pad_bytes, the result is left-padded with zero bytes to exactly
      pad_bytes length.

    Returns:
    - bytes: Raw bytes represented by the hex string, possibly left-padded.

    Example:
        hex_to_bytes("01", pad_bytes=2) -> b'\x00\x01'
    """
    b = bytes.fromhex(hexstr)
    if pad_bytes is not None and len(b) < pad_bytes:
        b = b.rjust(pad_bytes, b"\x00")
    return b


def calculate_u(hash_name, A_hex, B_hex, N_hex):
    """
    Calculate the scrambling parameter u = H(PAD(A) || PAD(B)).

    Parameters:
    - hash_name (str): Name of the hash algorithm to use (e.g. "SHA-1", "SHA-256", "SHA-384", "SHA-512").
    - A_hex (str): Client public value A as a hex string.
    - B_hex (str): Server public value B as a hex string.
    - N_hex (str): Group prime N as a hex string; used to determine padding length.

    Returns:
    - str: Uppercase hexadecimal digest of H(PAD(A) || PAD(B)).

    Raises:
    - ValueError: if an unsupported hash_name is provided.

    Behavior:
    - Pads A and B to the byte-length of N, concatenates PAD(A)||PAD(B), hashes the
      concatenation with the selected hash algorithm, and returns the hex digest
      in uppercase.
    """
    # Pad A and B to the byte length of N
    N = int(N_hex, 16)
    pad_bytes = (N.bit_length() + 7) // 8
    A_bytes = hex_to_bytes(A_hex, pad_bytes)
    B_bytes = hex_to_bytes(B_hex, pad_bytes)
    # Concatenate PAD(A) || PAD(B)
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
    N_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
    A_hex = "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"
    B_hex = "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58"
    hash_name = "SHA-1"
    u = calculate_u(hash_name, A_hex, B_hex, N_hex)
    print(f"u_obtained = {u}\n")
    u_hex_expected = "CE38B9593487DA98554ED47D70A7AE5F462EF019"  # RFC 5054
    print(f"u_expected = {u_hex_expected}\n")
    if u == u_hex_expected:
        print("u = H(PAD(A)| PAD(B)) values match for RFC vector tests")
    else:
        print("u = H(PAD(A)| PAD(B)) values don't match for RFC vector tests")
