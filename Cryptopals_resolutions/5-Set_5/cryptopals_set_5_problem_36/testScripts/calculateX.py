import hashlib


def calculate_x(hash_name, salt_hex, username, password):
    """
    /**
     * @brief Calculates the SRP private key 'x' according to RFC 5054.
     *
     * Formula: x = SHA-<alg>(salt | SHA-<alg>(username | ":" | password))
     *
     * @param hash_name The hash algorithm to use ("SHA-1", "SHA-256", "SHA-384", "SHA-512").
     * @param salt_hex The salt value as a hexadecimal string.
     * @param username The username as a string.
     * @param password The password as a string.
     * @return The computed 'x' value as an uppercase hexadecimal string.
     * @throws ValueError if the hash_name is not supported.
     *
     * Example (RFC 5054 test vector):
     *   salt_hex = "BEB25379D1A8581EB5A727673A2441EE"
     *   username = "alice"
     *   password = "password123"
     *   hash_name = "SHA-1"
     *   x = calculate_x(hash_name, salt_hex, username, password)
     *   # x == "94B7555AABE9127CC58CCF4993DB6CF84D16C124"
     */
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
    print(f"x = {x}")
    print(f"x_expected = {x_expected}")
