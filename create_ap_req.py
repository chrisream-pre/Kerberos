import binascii
import os
import secrets

from pyasn1.type import univ, tag, namedtype, char
from pyasn1.codec.der import encoder

# Define AP-REQ ASN.1 structure (simplified)
class APReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pvno', univ.Integer()),                # Protocol version
        namedtype.NamedType('msg-type', univ.Integer()),            # AP_REQ = 14
        namedtype.NamedType('ap-options', univ.BitString()),        # Bit flags
        namedtype.NamedType('TGT', univ.OctetString()),             # TGT (opaque blob)
        namedtype.NamedType('Authenticator', univ.OctetString())    # Encrypted Authenticator (opaque blob)
    )

def construct_ap_req(tgt_bytes, authenticator_bytes):
    print("\nConstructing AP-REQ structure...")
    ap_req = APReq()
    ap_req.setComponentByName('pvno', 5)
    ap_req.setComponentByName('msg-type', 14)  # Message type for AP-REQ
    ap_req.setComponentByName('ap-options', univ.BitString("'00000000'B"))  # No special options
    ap_req.setComponentByName('TGT', tgt_bytes)
    ap_req.setComponentByName('Authenticator', authenticator_bytes)

    print("\nAP-REQ Structure (before DER encoding):")
    print(ap_req.prettyPrint())

    encoded_ap_req = encoder.encode(ap_req)
    print("\nDER-encoded AP-REQ (hex):")
    print(binascii.hexlify(encoded_ap_req).decode())
    print(f"\nTotal Length: {len(encoded_ap_req)} bytes")

def main():
    print("Kerberos AP_REQ Generator")
    choice = input("Use randomized TGT and Authenticator? (y/N): ").strip().lower()
    use_random = choice == 'y'

    if use_random:
        tgt = secrets.token_bytes(128)
        authenticator = secrets.token_bytes(96)
        print("Generated random TGT (128 bytes) and Authenticator (96 bytes).")
    else:
        tgt = binascii.unhexlify(
            "6d574bdd17cc5e2125531e42616e4798281dd5e3a30cb44eef7d07fea9f9e43c43863763dc0b716c7979978e8401afc2"
            "d74c22b80dac092d046b6a60c071b489cb61eb2158e633e4fe66a1a7dfc924a2"
        )
        authenticator = binascii.unhexlify(
            "06d74bdd17cc5e2125531e42616e4798281dd5e3a30cb44eef7d07fea9f9e43c43863763dc0b716c7979978e8401afc2"
            "d74c22b80dac092d046b6a60c071b489cb61eb2158e633e4fe66a1a7dfc924a2"
        )
        print("Using hardcoded example values for TGT and Authenticator.")

    print("\nTGT (hex):")
    print(binascii.hexlify(tgt).decode())

    print("\nAuthenticator (hex):")
    print(binascii.hexlify(authenticator).decode())

    construct_ap_req(tgt, authenticator)

if __name__ == '__main__':
    main()
