"""
calculateX.py

Compute the SRP private key x as defined in RFC 5054:

    x = H( salt || H( username || ":" || password ) )

This module provides:
- calculate_x(hash_name, salt_hex, username, password) -> str
    Computes the 'x' value using the requested hash algorithm and returns it
    as an uppercase hexadecimal string (no "0x" prefix).

Notes:
- salt_hex must be a hex string (uppercase or lowercase) representing the salt.
- hash_name supports: "SHA-1", "SHA-256", "SHA-384", "SHA-512" (case-insensitive).
- The returned hex string matches RFC 5054 test vectors when using the
  corresponding inputs.
"""

import hashlib


def calculate_x(hash_name, salt_hex, username, password):
    """
    Calculate the SRP private key 'x' according to RFC 5054.

    Formula:
        x = H( salt || H( username || ":" || password ) )

    Parameters:
    - hash_name (str): Hash algorithm name (e.g. "SHA-1", "SHA-256", "SHA-384", "SHA-512").
    - salt_hex (str): Salt as a hexadecimal string (no "0x" prefix).
    - username (str): Username string.
    - password (str): Password string.

    Returns:
    - str: Computed 'x' value as an uppercase hexadecimal string.

    Raises:
    - ValueError: if an unsupported hash_name is provided.

    Example:
        salt_hex = "BEB25379D1A8581EB5A727673A2441EE"
        username = "alice"
        password = "password123"
        x = calculate_x("SHA-1", salt_hex, username, password)
        # x == "94B7555AABE9127CC58CCF4993DB6CF84D16C124"
    """
    # Convert salt from hex to bytes
    salt_bytes = bytes.fromhex(salt_hex)
    # x = SHA-<alg>(salt | SHA-<alg>(username | ":" | password))
    # Inner hash: SHA-<alg>(username | ":" | password)
    inner = f"{username}:{password}".encode("utf-8")
    hash_name = hash_name.lower().replace("-", "")
    if hash_name == "sha1":
        h_inner = hashlib.sha1()
        h_outer = hashlib.sha1()
    elif hash_name == "sha256":
        h_inner = hashlib.sha256()
        h_outer = hashlib.sha256()
    elif hash_name == "sha384":
        h_inner = hashlib.sha384()
        h_outer = hashlib.sha384()
    elif hash_name == "sha512":
        h_inner = hashlib.sha512()
        h_outer = hashlib.sha512()
    else:
        raise ValueError("Unsupported hash: " + hash_name)
    h_inner.update(inner)
    inner_hash = h_inner.digest()
    # Outer hash: SHA-<alg>(salt_bytes | inner_hash)
    h_outer.update(salt_bytes + inner_hash)
    return h_outer.hexdigest().upper()


if __name__ == "__main__":
    # Example usage (RFC 5054 test vector)
    salt_hex = "BEB25379D1A8581EB5A727673A2441EE"
    username = "alice"
    password = "password123"
    hash_name = "SHA-1"
    x = calculate_x(hash_name, salt_hex, username, password)
    x_expected = "94B7555AABE9127CC58CCF4993DB6CF84D16C124"
    print(f"x          = {x}\n")
    print(f"x_expected = {x_expected}\n")
    if x == x_expected:
        print("x value matches RFC-5054 test vector")
    else:
        print("x value does not match RFC-5054 test vector")
