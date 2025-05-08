import secrets

key_length = 64  # HMAC-SHA1 key size
random_key = secrets.token_bytes(key_length)
print(random_key.hex())  # Print hex representation if needed
