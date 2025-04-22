import secrets

key_length = 999  # Choose a secure length (e.g., 16 or 32 bytes)
random_key = secrets.token_bytes(key_length)
print(random_key.hex())  # Print hex representation if needed
