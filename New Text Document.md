```py
# Refs: https://stackoverflow.com/questions/9433541/movsx-in-python

def SIGNEXT(x, b):
    m = (1 << (b -1))
    x = x & ((1 << b) -1)
    return ((x ^ m) - m)
 
# This routine is responsible for decrypting the stored C2.
def rc4_customized_decryptor(data, key):
    idx = 0
    counter1 = 0
    counter2 = 0
     
    # Initialize RC4 S-box
    rc4Sbox = list(range(256))
     
    # Modify RC4 S-box
    for i in range(256):
        counter2 += (rc4Sbox[i] + key[i%250])
        counter2 = counter2 & 0x000000FF
        rc4Sbox[i] ^= rc4Sbox[counter2]
        rc4Sbox[counter2 & 0xFF] ^= rc4Sbox[counter1 & 0xFF]
        rc4Sbox[counter1 & 0xFF] ^= rc4Sbox[counter2 & 0xFF]
        counter1 = i+1       
     
    # Decrypt data
    counter1 = 0
    counter2 = 0
    j = 0
    decrypted = []
    while(idx < len(data)):
        counter1 = j + 1
        k = (j+1)
        rc4Sbox_value1 = rc4Sbox[k]
        counter2 += (SIGNEXT(rc4Sbox_value1, 8) & 0xFFFFFFFF)
        rc4Sbox_value1_ = (SIGNEXT(rc4Sbox_value1, 8) & 0xFFFFFFFF)
        rc4Sbox_value2 = rc4Sbox[counter2 & 0x000000FF]
        rc4Sbox[k] = rc4Sbox_value2
        rc4Sbox[(counter2 & 0x000000FF)] = rc4Sbox_value1
        tmp1 = rc4Sbox[((0x20 * counter1) ^ (counter2 >> 3)) & 0x000000FF]
        tmp2 = rc4Sbox[((0x20 * counter2) ^ (counter1 >> 3)) & 0x000000FF]
        tmp3 = rc4Sbox[((tmp1 + tmp2) & 0x000000FF) ^ 0xAA]
        tmp4 = rc4Sbox[(rc4Sbox_value2 + rc4Sbox_value1_) & 0x000000FF]
        tmp5 = (tmp3 + tmp4) & 0x000000FF
        tmp6 = rc4Sbox[(counter2 + rc4Sbox_value2) & 0x000000FF]
        decrypted.append(data[idx] ^ (tmp5 ^ tmp6))
         
        counter1 += 1
        j = counter1
        idx += 1
     
    return bytes(decrypted)

def unicode_strings(buf, n=4):
    import re
    ASCII_BYTE = b' !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t'
    if type(buf) == str:
        buf = buf.encode('utf-8')
    reg = b'((?:[%s]\x00){%d,})' % (ASCII_BYTE, n)
    uni_re = re.compile(reg)
    out = []
    for match in uni_re.finditer(buf):
        try:
            out.append(match.group().decode("utf-16"))
        except UnicodeDecodeError:
            continue
    return out

import pefile
import struct

# Load the PE file using pefile
pe = pefile.PE(r"") # Put your file path

# Initialize variable to store .bss section data
bss_section_data = None

# Iterate through sections to find the .bss section
for section in pe.sections:
    section_name = section.Name
    if section_name.startswith(b'.bss'):
        bss_section_data = section.get_data()

# Extract the key size and key from the .bss section
key_size = struct.unpack('<I', bss_section_data[:4])[0]
key = bss_section_data[4:4 + key_size]

# because the key is 250 bytes. We extracted 50 bytes from bss section and fill the rest with zeros
key = key + b'\x00' * (250 - len(key))

# Extract encrypted data from the .bss section
enc_data = bss_section_data[4 + key_size:]
enc_data = enc_data.split(b'\x00\x00\x00\x00\x00\x00\x00\x00')[0]

# Decrypt the encrypted data using a custom RC4 decryptor
dec_data = rc4_customized_decryptor(enc_data, key)

# Extract C2 host length and host string
host_len = struct.unpack('<I', dec_data[:4])[0]
host_wide = dec_data[4:host_len+4]
c2_host = unicode_strings(host_wide)[0]

# Extract C2 port
c2_port = struct.unpack('<H', dec_data[host_len+4:host_len+4+2])[0]

# Print the extracted C2 host and port
print("C2 host: %s, port: %d" % (c2_host, c2_port))

```