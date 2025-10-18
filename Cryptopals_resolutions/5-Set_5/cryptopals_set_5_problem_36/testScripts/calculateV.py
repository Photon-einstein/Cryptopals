"""
calculateV.py

Compute the SRP verifier v = g^x mod N for SRP groups defined in
../input/SrpParameters.json.

Module provides:
- concat_hex_lines(hex_lines): join multi-line hex representations into a single hex string.
- calculate_v(x_hex, N_hex, g): compute verifier v as uppercase hex, padded to the byte-length of N.
- main(): example/demo that computes v for configured SRP groups and prints RFC-5054 expected value for group 1.

Notes:
- All hex inputs/outputs are uppercase and do not include the "0x" prefix.
- Output is padded to the byte-length of N to ensure consistent formatting across implementations.
"""

import json


def concat_hex_lines(hex_lines):
    """Concatenate a list of hex string lines into a single normalized hex string.

    Parameters:
    - hex_lines (Iterable[str]): lines that together represent a hex number,
      possibly containing spaces or newlines.

    Returns:
    - str: a single hex string with whitespace removed.

    Example:
        concat_hex_lines(["AA BB", "CC"]) -> "AABBCC"
    """
    return "".join(hex_lines).replace("\n", "").replace(" ", "")


def calculate_v(x_hex, N_hex, g):
    """
    Calculates the SRP verifier v according to RFC 5054:
    v = g^x mod N

    Parameters:
    - x_hex (str): The private key x as a hexadecimal string.
    - N_hex (str): The group prime N as a hexadecimal string.
    - g (int): The generator g as an integer.

    Returns:
    - str: The verifier v as an uppercase hexadecimal string, zero-padded
      to the byte-length of N for consistent output.

    Example:
        calculate_v("94B7...", N_hex, 2) -> "7E27..."
    """
    x = int(x_hex, 16)
    N = int(N_hex, 16)
    v = pow(g, x, N)
    # Pad to the byte length of N for consistent output
    byte_len = (N.bit_length() + 7) // 8
    v_hex = format(v, "0{}X".format(byte_len * 2))
    return v_hex


def main():
    """Load SRP group parameters and print verifier v for each group.

    Uses the x value from the RFC 5054 test vector and prints the expected
    verifier for group 1 for verification purposes.
    """
    with open("../input/SrpParameters.json", "r") as f:
        params = json.load(f)

    x_hex = "94B7555AABE9127CC58CCF4993DB6CF84D16C124"  # RFC 5054 x value
    v_expected = "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB"

    for group in params["srpGroups"]:
        group_id = group.get("groupId")
        N_hex = concat_hex_lines(group["primeN"])
        g_int = group["generatorG"]
        v_hex = calculate_v(x_hex, N_hex, g_int)
        print(f"Group {group_id}: v = {v_hex}")
        if group_id == 1:
            print(f"Group {group_id}: v_expected = {v_expected}")
        print()


if __name__ == "__main__":
    main()
