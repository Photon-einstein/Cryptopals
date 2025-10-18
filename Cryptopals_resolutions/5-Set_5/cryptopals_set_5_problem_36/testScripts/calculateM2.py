"""
calculateM2.py

Utilities to compute the SRP server proof M2 = H(A | M | K).

This module provides:
- hex_to_bytes(hexstr) -> bytes
    Convert a hex string to raw bytes.

- calculateM2(hash_name, A_hex, M_hex, K_hex) -> str
    Compute M2 = H(A || M || K) where A, M, K are provided as hex strings
    and H is the selected hash function (SHA-1, SHA-256, SHA-384, SHA-512).

Behavior and notes:
- All inputs are expected to be hex strings without "0x" prefix.
- The returned digest is an uppercase hex string to match project conventions.
- This is a small test/tool script intended for verification using known
  RFC 5054 vectors.
"""

import hashlib


def hex_to_bytes(hexstr: str) -> bytes:
    """
    Convert a hexadecimal string to bytes.

    Parameters:
    - hexstr: Hexadecimal string (may be upper/lower case, no "0x" prefix).

    Returns:
    - bytes: Raw bytes represented by the hex string.

    Raises:
    - ValueError if the input contains non-hex characters or has odd length.
    """
    return bytes.fromhex(hexstr)


def calculateM2(hash_name: str, A_hex: str, M_hex: str, K_hex: str) -> str:
    """
    Calculate M2 = H(A | M | K) for SRP.

    Parameters:
    - hash_name: Name of the hash algorithm (e.g. "SHA-1", "SHA-256", "SHA-384", "SHA-512").
    - A_hex: Client public value A as a hex string.
    - M_hex: Client proof M as a hex string.
    - K_hex: Session key K as a hex string.

    Returns:
    - Uppercase hex digest string of H(A || M || K).

    Raises:
    - ValueError if an unsupported hash_name is provided.
    """
    A_bytes = hex_to_bytes(A_hex)
    M_bytes = hex_to_bytes(M_hex)
    K_bytes = hex_to_bytes(K_hex)
    input_bytes = A_bytes + M_bytes + K_bytes

    hn = hash_name.lower().replace("-", "")
    if hn == "sha1":
        h = hashlib.sha1()
    elif hn == "sha256":
        h = hashlib.sha256()
    elif hn == "sha384":
        h = hashlib.sha384()
    elif hn == "sha512":
        h = hashlib.sha512()
    else:
        raise ValueError(f"Unsupported hash: {hash_name}")

    h.update(input_bytes)
    return h.hexdigest().upper()


if __name__ == "__main__":
    """
    Example usage with RFC 5054 test vectors.

    Running this script will print M2 values for a set of precomputed M and K
    values for several hash algorithms. Use this to verify implementations.
    """
    # Example RFC 5054 test vector values
    A_hex = (
        "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E890"
        "3211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E"
        "42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261"
        "EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"
    )

    # Precalculated M and K values for each hash (from RFC / project test vectors)
    values = {
        "SHA-1": {
            "M_hex": "3F3BC67169EA71302599CF1B0F5D408B7B65D347",
            "K_hex": "017EEFA1CEFC5C2E626E21598987F31E0F1B11BB",
        },
        "SHA-256": {
            "M_hex": "79BD06B66CE6C85E02A85BBD80D5CE6CA4A0A86939B7D0F913012C6101A77546",
            "K_hex": "C370461D9D28F31C1D20F988907C3FB8EDA57B7AA2EC149ECB2260D8E91A9931",
        },
        "SHA-384": {
            "M_hex": "C0318E36BC854EFAE4D8ECD18A4CA1EC95A67A672A4EC2BCF170B577D312DA80AB26BEED788AB9713326AEDB3E9A0297",
            "K_hex": "D4E3B2E5ABCCF9F54EB12F55D4B26A23BAA11541414F4CAB7CDC185C5C28C69D0BD0B66F353EABCD63B748CEAB45D8FC",
        },
        "SHA-512": {
            "M_hex": "8AE46F403CAEA982FCF3E34A3DDFDC9265059DBEA08F0C45A4E0B9672904C343C8FD087B0C23F8E0261D0E1FEDD730CD6DDC74EC53EA09D5CD920DB5EE2F8E27",
            "K_hex": "EB86BD35F055213D911E74BA485D516D2C7D648ECA4FD7C4FD474CF9FFF1D3A8B0EFCB6BC0F2B07530BD02D6EA12F85F550B136958F783E4B84D47F727AE4B23",
        },
    }

    for hash_name, pair in values.items():
        M_hex = pair["M_hex"]
        K_hex = pair["K_hex"]
        M2 = calculateM2(hash_name, A_hex, M_hex, K_hex)
        print(f"{hash_name} M2: {M2}")


# M values
# SHA-1: 3F3BC67169EA71302599CF1B0F5D408B7B65D347
# SHA-256: 79BD06B66CE6C85E02A85BBD80D5CE6CA4A0A86939B7D0F913012C6101A77546
# SHA-384: C0318E36BC854EFAE4D8ECD18A4CA1EC95A67A672A4EC2BCF170B577D312DA80AB26BEED788AB9713326AEDB3E9A0297
# SHA-512: 8AE46F403CAEA982FCF3E34A3DDFDC9265059DBEA08F0C45A4E0B9672904C343C8FD087B0C23F8E0261D0E1FEDD730CD6DDC74EC53EA09D5CD920DB5EE2F8E27

# K values
# SHA-1: 017EEFA1CEFC5C2E626E21598987F31E0F1B11BB
# SHA-256: C370461D9D28F31C1D20F988907C3FB8EDA57B7AA2EC149ECB2260D8E91A9931
# SHA-384: D4E3B2E5ABCCF9F54EB12F55D4B26A23BAA11541414F4CAB7CDC185C5C28C69D0BD0B66F353EABCD63B748CEAB45D8FC
# SHA-512: EB86BD35F055213D911E74BA485D516D2C7D648ECA4FD7C4FD474CF9FFF1D3A8B0EFCB6BC0F2B07530BD02D6EA12F85F550B136958F783E4B84D47F727AE4B23

# M2 values
# SHA-1 M2: 9CAB3C575A11DE37D3AC1421A9F009236A48EB55
# SHA-256 M2: 491F3622627F1E942E64D9D61BD64BCB3796B697805EF7E279A57C01C7B63222
# SHA-384 M2: 6D4F1C4FFE20286D0263F10BB4917ECC5C77B70DC453158CC43F0ED1DB2C430E0A14A68B9420C8E956A41DC5D2E3218F
# SHA-512 M2: 5C0EFFC6FB406E41E908D0B985F037128C88AC74A235EABB82FBAEBD8B3B7E8A7238EAA1A1541ABAC609C2DBAD15C7A30E79CCAB0C65AC4AA5226E78E2596BC4
