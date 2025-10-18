"""
calculateK.py

Utilities to compute the SRP session key K from the shared secret S.

This module exposes:
- calculateK(hash_name: str, S_hex: str) -> str
  Computes K = H(S) where S is provided as a hex string and H is the chosen
  hash function (SHA-1, SHA-256, SHA-384, SHA-512). The returned value is an
  uppercase hex digest.

Usage:
    from calculateK import calculateK
    K_hex = calculateK("SHA-256", "<S as hex>")
"""

import hashlib
from typing import Callable


def _get_hash_constructor(hash_name: str) -> Callable[[], "hashlib._HASH"]:
    """Return a hashlib constructor for the given hash name (case-insensitive)."""
    hn = hash_name.replace("-", "").lower()
    if hn == "sha1":
        return hashlib.sha1
    if hn == "sha256":
        return hashlib.sha256
    if hn == "sha384":
        return hashlib.sha384
    if hn == "sha512":
        return hashlib.sha512
    raise ValueError(f"Unsupported hash: {hash_name}")


def calculateK(hash_name: str, S_hex: str) -> str:
    """
    Calculate the SRP session key K as the hash of the shared secret S.

    Parameters:
    - hash_name: Hash algorithm name (e.g. "SHA-1", "SHA-256", "SHA-384", "SHA-512").
    - S_hex: Shared secret S encoded as a hex string (case-insensitive, no 0x).

    Returns:
    - Uppercase hex string of H(S).

    Raises:
    - ValueError if the hash algorithm is unsupported.
    """
    S_bytes = bytes.fromhex(S_hex)
    h_ctor = _get_hash_constructor(hash_name)
    h = h_ctor()
    h.update(S_bytes)
    return h.hexdigest().upper()


if __name__ == "__main__":
    # Example S value (hex string)
    S_hex = (
        "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E3"
        "59B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C"
        "00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB3394"
        "3CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"
    )
    hash_algorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]
    for hash_name in hash_algorithms:
        K_hex = calculateK(hash_name, S_hex)
        print(f"{hash_name}: {K_hex}")
