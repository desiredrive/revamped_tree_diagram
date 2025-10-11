KEY_HEX = (
    0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x6F, 0x41, 0x2C,
    0x2E, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6B, 0x6C, 0x64, 0x4A,
    0x4B, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63,
    0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6E, 0x63, 0x78, 0x76,
    0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6B, 0x3B, 0x66,
    0x67, 0x38, 0x37
)

def decrypt_password(encrypted: str):
    """
    Decrypt a string as a Cisco Type 7 password.
    Returns True/False (as decryption_ok), result:
      - decryption_ok = True => result is the decrypted plaintext
      - decryption_ok = False => result is an error message
    """
    if len(encrypted) < 4 or len(encrypted) > 52 or (len(encrypted) % 2) != 0:
        return (False, "Error! Bad password length.")

    try:
        offset = int(encrypted[:2])  # decimal parse (e.g. '15' => offset=15)
        if not 0 <= offset <= 15:
            return (False, "Error! Bad key offset.")

        hex_payload = encrypted[2:]
        plaintext = []
        for i in range(0, len(hex_payload), 2):
            enc_val = int(hex_payload[i: i + 2], 16)
            key_val = KEY_HEX[((i // 2) + offset) % len(KEY_HEX)]
            dec_val = enc_val ^ key_val
            plaintext.append(chr(dec_val))
        return (True, "".join(plaintext))

    except ValueError:
        return (False, "Error! Invalid encryption data.")
