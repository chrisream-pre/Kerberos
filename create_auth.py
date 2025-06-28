from pyasn1.type import univ, char, namedtype, tag, useful
from pyasn1.codec.der import encoder
import datetime
import binascii
import os
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

# Define PrincipalName
class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name-type', univ.Integer()),
        namedtype.NamedType('name-string', univ.SequenceOf(componentType=char.GeneralString()))
    )

# Define EncryptionKey
class EncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keytype', univ.Integer()),
        namedtype.NamedType('keyvalue', univ.OctetString())
    )

# Define Authenticator
class Authenticator(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('authenticator-vno', univ.Integer()),
        namedtype.NamedType('crealm', char.GeneralString()),
        namedtype.NamedType('cname', PrincipalName()),
        namedtype.NamedType('cusec', univ.Integer()),
        namedtype.NamedType('ctime', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('subkey', EncryptionKey().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),
        namedtype.OptionalNamedType('seq-number', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)))
    )

def aes256_cts_encrypt(key, plaintext):
    iv = b'\x00' * 16  # Kerberos-style zero IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)

def create_authenticator(use_random=False):
    if use_random:
        session_key = secrets.token_bytes(32)
        seq_number = int.from_bytes(os.urandom(4), 'big')
    else:
        session_key = bytes.fromhex('11' * 32)
        seq_number = 0xE240

    print(f"\nUsing session key (K_c,tgs): {binascii.hexlify(session_key).decode()} ({len(session_key)} bytes)")
    print(f"Using seq-number: {seq_number:#x}")

    print("\n[+] Constructing the Authenticator..")

    auth = Authenticator()
    auth.setComponentByName('authenticator-vno', 5)
    auth.setComponentByName('crealm', 'PRAIRIE-FIRE.LAB')

    cname = PrincipalName()
    cname.setComponentByName('name-type', 1)
    name_string = univ.SequenceOf(componentType=char.GeneralString())
    name_string.append('gabriela')
    cname.setComponentByName('name-string', name_string)
    auth.setComponentByName('cname', cname)

    now = datetime.datetime.now(datetime.timezone.utc)
    auth.setComponentByName('cusec', now.microsecond // 1000)
    auth.setComponentByName('ctime', useful.GeneralizedTime(now.strftime('%Y%m%d%H%M%SZ')))

    subkey = EncryptionKey()
    subkey.setComponentByName('keytype', 18)
    subkey.setComponentByName('keyvalue', univ.OctetString(b'\xaa' * 32))
    subkey = subkey.subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))
    auth.setComponentByName('subkey', subkey)

    seq = univ.Integer(seq_number).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
    )
    auth.setComponentByName('seq-number', seq)

    print("\nAuthenticator structure before encoding:")
    print(auth.prettyPrint())

    encoded = encoder.encode(auth)
    print("\nAuthenticator DER-encoded (hex):")
    print(binascii.hexlify(encoded).decode())
    print(f"\nDER length: {len(encoded)} bytes")

    print("\nEncrypting Authenticator with AES256-CBC (Kerberos-style zero IV)...")
    encrypted_blob = aes256_cts_encrypt(session_key, encoded)
    print("\nEncrypted Authenticator blob (hex):")
    print(binascii.hexlify(encrypted_blob).decode())

    print("\nSimulated .kirbi-style blob (Base64):")
    print(base64.b64encode(encrypted_blob).decode())

def main():
    print("Kerberos Authenticator Generator + Encryptor")
    choice = input("Use randomized session key and seq-number? (y/N): ").strip().lower()
    use_random = choice == 'n'
    create_authenticator(use_random)

if __name__ == '__main__':
    main()
