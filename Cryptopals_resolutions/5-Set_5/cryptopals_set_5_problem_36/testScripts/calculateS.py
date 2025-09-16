import hashlib

def hex_to_int(h):
    return int(h, 16)

def calculate_k(N_hex, g, hash_name):
    N_bytes = bytes.fromhex(N_hex)
    g_bytes = g.to_bytes((g.bit_length() + 7) // 8, 'big')
    g_padded = b'\x00' * (len(N_bytes) - len(g_bytes)) + g_bytes
    input_bytes = N_bytes + g_padded
    h = getattr(hashlib, hash_name.lower().replace('-', ''))
    k = h(input_bytes).hexdigest()
    return int(k, 16)

def calculate_S(B_hex, k, g, x_hex, a_hex, u_hex, N_hex):
    B = hex_to_int(B_hex)
    x = hex_to_int(x_hex)
    a = hex_to_int(a_hex)
    u = hex_to_int(u_hex)
    N = hex_to_int(N_hex)
    gx = pow(g, x, N)
    kgx = (k * gx) % N
    base = (B - kgx) % N
    exp = (a + u * x) % N
    S = pow(base, exp, N)
    return format(S, 'X')  # Uppercase hex

if __name__ == "__main__":
    # Example values
    N_hex = "EEAF0AB9ADB38DD69C33F80AFA8FC5E8607261877519..."
    g = 2
    hash_name = "sha256"
    B_hex = "B1B2B3B4..."  # Server public value (hex)
    x_hex = "A1A2A3A4..."  # Private key parameter x (hex)
    a_hex = "C1C2C3C4..."  # Client private ephemeral a (hex)
    u_hex = "D1D2D3D4..."  # Scrambling parameter u (hex)

    # Calculate k
    k = calculate_k(N_hex, g, hash_name)
    # Calculate S
    S_hex = calculate_S(B_hex, k, g, x_hex, a_hex, u_hex, N_hex)
    print(f"S = {S_hex}")