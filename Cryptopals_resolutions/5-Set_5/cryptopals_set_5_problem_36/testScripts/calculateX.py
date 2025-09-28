import hashlib

def calculate_x(hash_name, salt_hex, password):
    # Convert salt from hex to bytes
    salt_bytes = bytes.fromhex(salt_hex)
    # Encode password as bytes (UTF-8)
    password_bytes = password.encode('utf-8')
    # Concatenate salt || password
    input_bytes = salt_bytes + password_bytes
    # Select hash function
    hash_name = hash_name.lower().replace('-', '')
    if hash_name == 'sha256':
        h = hashlib.sha256()
    elif hash_name == 'sha384':
        h = hashlib.sha384()
    elif hash_name == 'sha512':
        h = hashlib.sha512()
    else:
        raise ValueError("Unsupported hash: " + hash_name)
    h.update(input_bytes)
    return h.hexdigest().upper()

if __name__ == "__main__":
    # Example usage
    salt_hex = (
        "6B479DEBFE96BB93AC51E60F534536E4E493549EE1DA41A145E415612"
        "FFBA766A2CEAF2BFB2DAF34585EF383E860EBD6C44627FAE2B88341F9"
        "BDA494A8B55D62")
    password = "correct horse battery staple"
    hash_name = "SHA-512"
    x = calculate_x(hash_name, salt_hex, password)
    print(f"x = {x}")
