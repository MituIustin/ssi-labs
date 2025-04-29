from Crypto.Cipher import DES

plaintext = b"Provocare MitM!!"  
ciphertext = b"G\xfd\xdfpd\xa5\xc9'C\xe2\xf0\x84)\xef\xeb\xf9"

middle_dict = {}

for k1 in range(256):
    key1 = bytes([k1, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # ?0...
    cipher1 = DES.new(key1, DES.MODE_ECB)
    middle = cipher1.encrypt(plaintext)
    middle_dict[middle] = key1

for k2 in range(256):
    key2 = bytes([k2, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    cipher2 = DES.new(key2, DES.MODE_ECB)
    middle_candidate = cipher2.decrypt(ciphertext)
    
    if middle_candidate in middle_dict:
        found_key1 = middle_dict[middle_candidate]
        found_key2 = key2
        print(f"Found Key")
        print(f"Key1: {found_key1.hex()}")
        print(f"Key2: {found_key2.hex()}")
        break
