"""
calculateSClient.py

Utilities to compute the SRP shared secret S on the client side.

This module provides:
- hex_to_int(h) -> int
    Convert a hex string to an integer.

- calculateSClient(B_hex, k, g, x_hex, a_hex, u_hex, N_hex, hash_name, debug=False) -> str
    Compute the SRP client shared secret S using the formula:

        S = (B - k * g^x)^(a + u * x) mod N

  Parameters:
  - B_hex: server public value B as a hex string.
  - k: multiplier parameter k as int (if None or not int, calculated via calculate_k).
  - g: generator as integer.
  - x_hex: private exponent x as hex string (derived from username/salt/password).
  - a_hex: client private exponent a as hex string.
  - u_hex: scrambling parameter u as hex string.
  - N_hex: modulus N as a hex string.
  - hash_name: name of the hash algorithm (passed to calculate_k when needed).
  - debug: optional bool, when True prints debug info.

  Returns:
  - S_hex: shared secret S encoded as an uppercase hex string padded to the byte-length of N.

Notes:
- Inputs are expected to be hex strings without "0x" prefix.
- The function will compute k via calculate_k(N_hex, g, hash_name) if k is None or not an int.
- The returned hex string is zero-padded to the byte-length of N for interoperability.
"""

from calculate_k_MultiplierParameter import calculate_k


def hex_to_int(h):
    """
    Convert a hexadecimal string to an integer.

    Parameters:
    - h (str): Hexadecimal string (no "0x" prefix).

    Returns:
    - int: Integer value represented by the hex string.

    Example:
        hex_to_int("FF") -> 255
    """
    return int(h, 16)


def calculateSClient(B_hex, k, g, x_hex, a_hex, u_hex, N_hex, hash_name, debug=False):
    """
    Calculate the SRP client shared secret S.

    Formula (client side):
        S = (B - k * g^x)^(a + u * x) mod N

    Parameters:
    - B_hex (str): Server public value B in hex.
    - k (int or None): Multiplier parameter k as integer. If None or not int,
      it will be computed using calculate_k(N_hex, g, hash_name).
    - g (int): Generator integer.
    - x_hex (str): x value (derived from salt/username/password) in hex.
    - a_hex (str): Client private key 'a' in hex.
    - u_hex (str): Scrambling parameter u in hex.
    - N_hex (str): Prime modulus N in hex.
    - hash_name (str): Hash algorithm name used for calculating k if needed.
    - debug (bool): If True, prints debug information.

    Returns:
    - str: Uppercase hex string of the computed shared secret S, zero-padded to the byte-length of N.

    Behavior:
    - Converts hex inputs to integers, computes intermediate values, and performs
      modular exponentiation using Python's pow with modulus.
    - Ensures the output hex string length corresponds to the byte-length of N.
    """
    # Debug: print input parameters
    if debug:
        print("[DEBUG] calculate_S_Client input parameters:")
        print("  B_hex:", B_hex)
        print("  k:", k)
        print("  g:", g)
        print("  x_hex:", x_hex)
        print("  a_hex:", a_hex)
        print("  u_hex:", u_hex)
        print("  N_hex:", N_hex)
        print("  hash_name:", hash_name)
    # Calculate k using the imported function if needed
    if k is None or not isinstance(k, int):
        k_hex = calculate_k(N_hex, g, hash_name)
        k_hex = k_hex.strip()
        k = int(k_hex, 16)
        # print("[DEBUG] Calculated k (from calculate_k):", k_hex)
    B = int(B_hex, 16)
    x = int(x_hex, 16)
    a = int(a_hex, 16)
    u = int(u_hex, 16)
    N = int(N_hex, 16)
    gx = pow(g, x, N)
    kgx = (k * gx) % N
    base = (B - kgx) % N
    exp = (a + u * x) % N
    S = pow(base, exp, N)
    byte_len = (N.bit_length() + 7) // 8
    S_hex = format(S, "0{}X".format(byte_len * 2))
    return S_hex


if __name__ == "__main__":
    import json

    B_hex = "2355BA23D75381A1A03D215D6128A3D74F5507A40C5363F118BB9207B8CBC2F074E6F19E465657C4380390247904108EFEBA22812397EBCF6B2313304064F43EE94138E81844159F78A0B1B26A8872A6D55B924A1A0C31F8CF38A9FA19AC1AFAD45852124A8D1E7CC8B4C108B9104D840C59ED77192A65DDB5B05DDCAF9F269A722227B6991987B5DC7389F9EB84AC5D6E8E43E6A346BB4303DA1D81F6C967AA25D406DE8A09D7445F6214CFC3084F5C7C0FB19A64EF7D9BF6AE58575684509179ABC8E4ED8CCAD119D29240BAB8BDB5AA013B9D97AFB8170D2A38F9D2B3C0C1063157348DD65D44CF71295C3F57D5D0EDAC00129702890B66F41B992D26EA2ACB7831BD6A5AC674CEDC61E58BE85DD4749FE32956C7A1DDB0881597F7FD9B9A961330B00F8DE39857D2901B3E4DE22834469B63AB83360F680F81DA12C3AC2C2DF69AD0FD2FC9789BA20CF73E6B4D7468F6AD8486081B17540A97D2D994E3EDE66EAD1444D770A7327DCC101D38051A50860ABE7FB527DA5C6ECBE3F6F6CBB49DD62ACD21C8E1A0FFFC495284B536476C02BB6AA443BC5EB29D3E56D97D7F367FD870D3A786BE9AF0A3F0304FA95B276126E8695FC938D480559C11FE00C6815A1E3B175D20B51799CEED0DBF0288083288445C128D96333DA25C5FCCCC08285CA035514AE20C227322795D2247BDC9F743DB26DBA9B5E4C2F60B785DBB53C3C2F1D157F0E6D413072F9917CC84B228CB14415594F9561D293547FC6EC273CF1EAF966355EC3E4D24E56448888EBD877BA258DCC998865EF4CE4E6829D839AF8615894DFCD5590D3AEFEBD40B1AC452102639EB1F10058FE5200A83ED87B43E909583D7F2C3CCD5447B96C1AA6F69766F498AEC5B65EC3F13FB32AB6A2A4C29D45AA507F575979A03DCE1879C4782BEB515AAEDC7501F3D188E52EEC17B949B88A9C63C99594952A4D00F2E4EE31EB8F3E162E755AD83AB926566331D36B8C3D15269F7FBF4C8479A052BE8779B3BFBCAC34A8B9BEA90A9A4FBC4A2422E3EF3EE7683BAECC9C1ADF702C65BB5B0A65CEE415802C9AB947443119EA8D671AAAFE900CDC789C07B4CD4C3B95E810E6F595EE0F0A42CE68D1157B4BC0D6368D1546C31932799B44B1410C87F8062703C9C40622610528EE510AFB66E90E2AAF6F97AC1C74A4FC1E94029EFDD901E023F6C781BE5EEB0FFA69A3ED72CE6BB8CBF33FB4D86215FC1E9F712F650BBD3B8E218EEE37D627949207AD59CEAB0059BE88C5824DEA6C6AD3493E4DF5BA7409F0B45F2708157790783CE4CAE8F36C6BCFEF657237AEB7DD91459DF73EFEF9983840865760D3706727C4BAA27D900A712211624624C2D7D885EA8D7019C3E8BE4A91F56E9B61E81DDFF1921C30BAB091713B274C76E091F2C995478D139655DE93E1283555E7E956AE787DA764B949E9581A6"
    x_hex = "FAD1BEF738428C6DE0A2AC6A8BDF059C9E49D60D2C491F6A27B5082B9AA3CE03106749C4FF0CCCE56D59A3A471EF002787EE4990BAD952C968B2E74370A6B39D"
    a_hex = "14C0628BBB6CA1B95F993A0ACEA6F21E82FD8B32183D31A23333B2F042504854E85ACE509C99CE4520CDCE0FA79B392CB25C9597248416A8DE5BAA75C6602E765EDD38ECFA3E7B97C0C2B54A3498D4AB32F0C75095151D7ACEF19A85E937F9F5969CD6C66397F5063A5F772E5E0D4ACB7E31BCE5B658F3DAB7B5ED287CC2181B5A85A69C657C90C9F47F5E723166274CAADD34ED6968F7008EB2880AF75944F5BE2FFDA937276A6356E600B5B95D04CC95179944C091370F01F35228CB7F22F7B3A1208E0B6882E5CC274F2175E61501C66184B44A49919318E24329C8BC114865693C9D6C0BE90FF25515D691384B59EE597532C9A8A49C01DFD3D0B292D2C881321FE5B8C5F0F891B06F0DD79F66F2DB1A91266BE0033348D1986015B379E95E8597B1CF06B4D576D885E517166C8F2612C95517669423F7AC63A1B527D3C9FDB261B4694A94F6E0001C18376AB376D452BB1DF242D63876F2017D11F238E0DA9CD64E8F33D017127B47EEF86A531549625D2008A2BD862A15405C0CE03ACE2B199FCE24AD7B14FA3AFC8BD561FC62A271C9CDB1BFC47AE9F2247B78F924C141ABF2482B9731B36317C4516308F91E99992264DC72BAED6133AB73B6522622EB7E3FF0385608DF941AEF1EEFA5D79C33AC541A26A31DE9BEA44A69FD6517767C839B0AEFB9A7134650267A66C376831E4DAC83D529A45AFABB55FD123296DB12FBB0B57ABCAD96B7DCE98A368D47AA1A662499307FF805A526C8E4656AF62FFDC865717B6770793253B5639ACD5FB7E6BB7FAE57C34D136EFD326FA9A65BD42DA3F44BC34E939BE05A7DD943725A086FF49078978A26DE0A7E8CCCCA5E32612059D96B7EB7AA378311A80066CEDB0DFEA175723D47C832C3E8529E28E2BC2A6263567A85477C8F87BC4FAA1BEF1CE783356708DC698ABFB43D4849373770B0962BBCBE262F5A090EEF68DF1CDAEB19D95FC21F6D4EDA65AF2CCF7CFF14BEDC44596314C52F2695F13806294669B4684FFEEC5B39695FFCE3CDB52F195E4E0223C2A905BF09A15ED0BA14771A6440739010DA26B4B48366C769438465D95BE5962870F4CFC5FD8DE64C39E731DF9FAB4DE36C94214FA2C38550B15F605E2F28773FB5E8F8F84BF56EEBF47D168CE5A62732B48DC9A6A794150B77548714DC9E7D8138A5605241315385A755CC0730B351C00A3E02B66962182DF2A758255CF23FFFB4715F5B9D802B3F2884867C7BFA0AFA3CE30052E0C97BC1E7EE477DDA2D7ED94F645CAEDB0CC1DACA529EB66620056C5E127E29E5ACD571C988C129DB41C004EFC6A832B1D455F6579B108B7E14E56B83B896323328D81F929BE971E767ECC62B98B4A64B1CA721FCCE7C0C3EE04AF2E077CF116975B6EB3872DC7BB447509568376A4E930541DC85CDF2E22CE3692B8C4BEBF9217C148FCB4FB19B0C57"
    u_hex = "8B9C98C073DA46A190B272F877C47B2894A145599960C0570EBD0C54ED4462663E90AA7EE4033888D8D0BDE99C8AF1BD927D1713596FDF8A487667206DAB23D6"
    # Load SRP groups from JSON
    with open("../input/SrpParameters.json", "r") as f:
        srp_params = json.load(f)

    for group in srp_params["srpGroups"]:
        groupId = group["groupId"]
        g = group["generatorG"]
        hash_name = group["hash"]
        # Concatenate all N parts
        N_hex = "".join(group["primeN"])
        print(f"Group {groupId}: g={g}, hash={hash_name}")
        k = calculate_k(N_hex, g, hash_name)
        S_hex = calculateSClient(B_hex, k, g, x_hex, a_hex, u_hex, N_hex, hash_name)
        print(f"\nS_Group_{groupId} = {S_hex}\n")
        if groupId == 1:
            hash_name = "SHA-1"
            k = calculate_k(N_hex, g, hash_name)
            S_hex = calculateSClient(B_hex, k, g, x_hex, a_hex, u_hex, N_hex, hash_name)
            print(f"S_[SHA-1]_Group_{groupId} = {S_hex}\n")
        print(
            "-------------------------------------------------------------------------\n"
        )
