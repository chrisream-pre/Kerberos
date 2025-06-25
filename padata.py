from datetime import datetime, timezone
import hashlib
import os
from Crypto.Cipher import AES
from pyasn1.type import univ, namedtype, tag, useful
from pyasn1.codec.der.encoder import encode
import base64
import json

# Constants
username = "Gabriela"
realm = "PRAIRIE-FIRE.LAB"
password = "P@ssw0rd12!@"  # Updated password
salt = realm + username

print(f"[*] Using credentials:\n    Username: {username}\n    Realm: {realm}\n    Password: {password}")
print(f"[*] Derived salt for key generation: {salt}")

# Step 1: Derive Kuser key using PBKDF2
def derive_kuser(password, salt, iterations=4096, dklen=32):
    print("[*] Deriving Kuser key with PBKDF2 (HMAC-SHA1, 4096 iterations)...")
    key = hashlib.pbkdf2_hmac('sha1', password.encode(), salt.encode(), iterations, dklen)
    print(f"[+] Derived Kuser (hex): {key.hex()}")
    return key

kuser = derive_kuser(password, salt)

# Step 2 & 3: Build and encode ASN.1 Timestamp
class KerberosTime(useful.GeneralizedTime):
    pass

class Timestamp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('patimestamp', KerberosTime().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('pausec', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )

def encode_timestamp():
    print("[*] Creating current timestamp in UTC...")
    now = datetime.now(timezone.utc)
    formatted_time = now.strftime("%Y%m%d%H%M%SZ")
    print(f"    UTC Timestamp: {formatted_time}")
    print(f"    Microseconds: {now.microsecond}")
    ts = Timestamp()
    ts.setComponentByName('patimestamp', formatted_time)
    ts.setComponentByName('pausec', now.microsecond)
    encoded = encode(ts)
    print(f"[+] ASN.1 DER-encoded timestamp (hex): {encoded.hex()}")
    return encoded

asn1_data = encode_timestamp()

# Step 4: Encrypt timestamp using AES256-CBC
def encrypt_timestamp(asn1_data, kuser):
    print("[*] Encrypting timestamp with AES256-CBC...")
    iv = os.urandom(16)
    print(f"    IV (hex): {iv.hex()}")
    cipher = AES.new(kuser, AES.MODE_CBC, iv)
    pad_len = 16 - (len(asn1_data) % 16)
    print(f"    Padding with {pad_len} bytes (PKCS7)...")
    padded = asn1_data + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded)
    full_blob = iv + ciphertext
    print(f"[+] Encrypted padata blob (hex): {full_blob.hex()}")
    return full_blob

padata_value = encrypt_timestamp(asn1_data, kuser)

# Step 5: Construct padata field
padata = {
    "padata-type": 2,
    "padata-value (hex)": padata_value.hex(),
    "padata-value (base64)": base64.b64encode(padata_value).decode()
}

print("\n[*] Final padata field for AS-REQ:")
print(json.dumps(padata, indent=2))
