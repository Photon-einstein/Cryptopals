import hashlib
import hmac
import os

def hmac_sha1(hex_key: str, message: str) -> str:
    # Convert the hex key to bytes
    key_bytes = bytes.fromhex(hex_key)
    
    # Convert the message to bytes
    message_bytes = message.encode()

    # Compute HMAC-SHA1
    hmac_sha1 = hmac.new(key_bytes, message_bytes, hashlib.sha1)
    
    return hmac_sha1.hexdigest()

# Example usage
key_name = "KEY_SERVER_SET_4_PROBLEM_31"
hex_key = os.getenv(key_name)  # Fetch the key from environment variables
message = "foo"
mac = hmac_sha1(hex_key, message)

print("HMAC-SHA1:", mac)
