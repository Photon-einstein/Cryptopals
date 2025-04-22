import os
from Crypto.Hash import MD4

def md4_mac(key: bytes, message: str) -> bytes:
    # Create an MD4 hash object
    md4_hash = MD4.new()
    # Update the hash with the key and message
    md4_hash.update(key + message.encode())
    # Return the final MAC (digest)
    return md4_hash.digest()

# Example usage
key_name = "KEY_SERVER_SET_4_PROBLEM_30"
hex_key = os.getenv(key_name)

if hex_key is None:
    raise ValueError(f"Environment variable {key_name} is not set!")

# Convert the hexadecimal string to bytes
key = bytes.fromhex(hex_key)

message = "user=bob&amount=1000&timestamp=1700000000"
mac = md4_mac(key, message)
print(f"MD4 MAC: {mac.hex()}")
