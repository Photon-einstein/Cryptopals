"""
Utility to calculate SRP multiplier parameter k for configured SRP groups.

Reads ../input/SrpParameters.json and computes k = H(N || pad_left(g, len(N)))
for each group using the group's configured hash function.

Functions:
- concat_hex_lines: join multi-line hex representations into a single hex string.
- pad_left: left-pad a byte sequence with zeros to a target size.
- get_hash_func: maps a hash name string to a hashlib constructor.
- calculate_k: compute k given N (hex), g (int) and hash name.
- main: load parameters file and print k for each group.

The output hex digests are uppercase to match other tools in the project.
"""

import json
import hashlib


def concat_hex_lines(hex_lines):
    """
    Concatenate a list of hex string lines into a single normalized hex string.

    Parameters:
    - hex_lines (Iterable[str]): lines that together represent a hex number,
      possibly containing spaces or newlines.

    Returns:
    - str: a single hex string with whitespace removed (uppercase/lowercase not changed).

    Example:
    >>> concat_hex_lines(["AA BB", "CC"])
    'AABBCC'
    """
    return "".join(hex_lines).replace("\n", "").replace(" ", "")


def pad_left(data: bytes, size: int) -> bytes:
    """
    Left-pad a byte sequence with zero bytes until it reaches the given size.

    If data is already of length >= size, the original data is returned.

    Parameters:
    - data (bytes): input bytes to pad.
    - size (int): desired output length in bytes.

    Returns:
    - bytes: padded byte sequence.

    Example:
    >>> pad_left(b'\\x01', 2)
    b'\\x00\\x01'
    """
    if len(data) >= size:
        return data
    return b"\x00" * (size - len(data)) + data


def get_hash_func(hash_name):
    """
    Map a hash algorithm name to the corresponding hashlib constructor.

    Supported names (case-insensitive): 'sha1', 'sha-1', 'sha256', 'sha-256',
    'sha384', 'sha-384', 'sha512', 'sha-512'.

    Parameters:
    - hash_name (str): name of the hash algorithm.

    Returns:
    - Callable[[], _hashlib.HASH]: constructor for the requested hash.

    Raises:
    - ValueError: if the requested hash name is unsupported.
    """
    hash_name = hash_name.lower()
    if hash_name in ["sha1", "sha-1"]:
        return hashlib.sha1
    elif hash_name in ["sha256", "sha-256"]:
        return hashlib.sha256
    elif hash_name in ["sha384", "sha-384"]:
        return hashlib.sha384
    elif hash_name in ["sha512", "sha-512"]:
        return hashlib.sha512
    else:
        raise ValueError(f"Unsupported hash: {hash_name}")


def calculate_k(N_hex, g_int, hash_name):
    """
    Calculate the SRP multiplier k = H(N || pad_left(g, len(N))) using the given hash.

    Parameters:
    - N_hex (str): modulus N encoded as hex (may be multi-line concatenated).
    - g_int (int): generator g as integer.
    - hash_name (str): name of the hash algorithm to use (see get_hash_func).

    Returns:
    - str: hex digest (uppercase) of H(N || padded_g).

    Notes:
    - g is converted to its minimal big-endian byte representation and then
      left-padded with zero bytes to the length of N in bytes before hashing.
    """
    N_bytes = bytes.fromhex(N_hex)
    g_bytes = g_int.to_bytes((g_int.bit_length() + 7) // 8, "big")
    g_padded = pad_left(g_bytes, len(N_bytes))
    data = N_bytes + g_padded
    h = get_hash_func(hash_name)()
    h.update(data)
    return h.hexdigest().upper()


def main():
    """
    Load ../input/SrpParameters.json and print the computed k for each SRP group.

    Also prints a SHA-1 based k for groupId == 1 for compatibility checks.
    """
    with open("../input/SrpParameters.json", "r") as f:
        params = json.load(f)

    for group in params["srpGroups"]:
        group_id = group.get("groupId")
        N_hex = concat_hex_lines(group["primeN"])
        g_int = group["generatorG"]
        hash_name = group["hash"]
        k_hex = calculate_k(N_hex, g_int, hash_name)
        print(f"Group {group_id}: k = {k_hex}")
        if group_id == 1:
            hash_name = "SHA-1"
            k_hex = calculate_k(N_hex, g_int, hash_name)
            print(f"Group {group_id} [SHA-1]: k = {k_hex}")


if __name__ == "__main__":
    main()
