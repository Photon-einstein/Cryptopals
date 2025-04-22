import hashlib
import os

def sha1_mac(hex_key: str, message: str) -> str:
    # Convert the hex key to bytes
    
    key_bytes = bytes.fromhex(hex_key)
    # Convert the message to bytes
    message_bytes = message.encode()

    # Compute SHA1(key || message)
    sha1 = hashlib.sha1()
    sha1.update(key_bytes + message_bytes)
    
    return sha1.hexdigest()

# Example usage
key_name = "KEY_SERVER_SET_4_PROBLEM_29"
hex_key = os.getenv(key_name)
message = "user=bob&amount=1000&timestamp=1700000000"
mac = sha1_mac(hex_key, message)

print("SHA1 MAC:", mac)