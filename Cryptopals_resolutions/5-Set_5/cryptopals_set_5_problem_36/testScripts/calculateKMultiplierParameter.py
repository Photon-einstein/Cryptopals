import json
import hashlib


def concat_hex_lines(hex_lines):
    """Concatenate a list of hex string lines into a single hex string."""
    return "".join(hex_lines).replace("\n", "").replace(" ", "")


def pad_left(data: bytes, size: int) -> bytes:
    """Pad data with leading zeros to match the given size."""
    if len(data) >= size:
        return data
    return b"\x00" * (size - len(data)) + data


def get_hash_func(hash_name):
    """Return a hashlib constructor for the given hash name."""
    hash_name = hash_name.lower()
    if hash_name in ["sha1", "sha-1"]:
        return hashlib.sha1
    elif hash_name in ["sha256", "sha-256"]:
        return hashlib.sha256
    elif hash_name in ["sha384", "sha-384"]:
        return hashlib.sha384
    elif hash_name in ["sha512", "sha-512"]:
        return hashlib.sha512
    else:
        raise ValueError(f"Unsupported hash: {hash_name}")


def calculate_k(N_hex, g_int, hash_name):
    N_bytes = bytes.fromhex(N_hex)
    g_bytes = g_int.to_bytes((g_int.bit_length() + 7) // 8, "big")
    g_padded = pad_left(g_bytes, len(N_bytes))
    data = N_bytes + g_padded
    h = get_hash_func(hash_name)()
    h.update(data)
    return h.hexdigest().upper()


def main():
    with open("../input/SrpParameters.json", "r") as f:
        params = json.load(f)

    for group in params["srpGroups"]:
        group_id = group.get("groupId")
        N_hex = concat_hex_lines(group["primeN"])
        g_int = group["generatorG"]
        hash_name = group["hash"]
        k_hex = calculate_k(N_hex, g_int, hash_name)
        print(f"Group {group_id}: k = {k_hex}")
        if group_id == 1:
            hash_name = "SHA-1"
            k_hex = calculate_k(N_hex, g_int, hash_name)
            print(f"Group {group_id} [SHA-1]: k = {k_hex}")


if __name__ == "__main__":
    main()
