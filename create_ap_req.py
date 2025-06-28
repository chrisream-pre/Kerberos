import binascii
import base64
import secrets

from pyasn1.type import univ, namedtype, char, tag
from pyasn1.codec.der import encoder


# Dummy Ticket (TGT) and Authenticator Structures

class TicketDummy(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('realm', char.GeneralString()),
        namedtype.NamedType('sname', char.GeneralString()),
        namedtype.NamedType('enc-part', univ.OctetString())
    )


class AuthenticatorDummy(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cname', char.GeneralString()),
        namedtype.NamedType('timestamp', char.GeneralString()),
        namedtype.NamedType('session-key', univ.OctetString())
    )


# Simplified AP-REQ Structure (padata-value)

class APReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pvno', univ.Integer()),                # Kerberos v5
        namedtype.NamedType('msg-type', univ.Integer()),            # AP_REQ = 14
        namedtype.NamedType('ap-options', univ.BitString()),        # Bit flags
        namedtype.NamedType('ticket', univ.OctetString()),          # DER TGT blob
        namedtype.NamedType('authenticator', univ.OctetString())    # DER Authenticator blob
    )


def generate_dummy_tgt():
    tgt = TicketDummy()
    tgt.setComponentByName('realm', 'PRAIRIE-FIRE.LAB')
    tgt.setComponentByName('sname', 'krbtgt')
    tgt.setComponentByName('enc-part', univ.OctetString(secrets.token_bytes(48)))
    return encoder.encode(tgt)


def generate_dummy_authenticator():
    auth = AuthenticatorDummy()
    auth.setComponentByName('cname', 'gabriela')
    auth.setComponentByName('timestamp', '20250629123456Z')  # Fixed for consistency
    auth.setComponentByName('session-key', secrets.token_bytes(32))
    return encoder.encode(auth)


def construct_ap_req(tgt_der, auth_der):
    print("\nConstructing ASN.1 AP-REQ structure...")
    ap_req = APReq()
    ap_req.setComponentByName('pvno', 5)
    ap_req.setComponentByName('msg-type', 14)
    ap_req.setComponentByName('ap-options', univ.BitString("'00000000'B"))
    ap_req.setComponentByName('ticket', univ.OctetString(tgt_der))
    ap_req.setComponentByName('authenticator', univ.OctetString(auth_der))

    print("\nAP-REQ (before DER encoding):")
    print(ap_req.prettyPrint())

    encoded = encoder.encode(ap_req)
    print("\nDER-encoded AP-REQ (hex):")
    print(binascii.hexlify(encoded).decode())
    print("\nDER-encoded AP-REQ (base64):")
    print(base64.b64encode(encoded).decode())
    print(f"\nFinal AP-REQ Length: {len(encoded)} bytes")


def main():
    print("Kerberos AP-REQ Generator")
    choice = input("Use randomized DER blobs for TGT and Authenticator? (y/N): ").strip().lower()
    use_random = choice == 'y'

    if use_random:
        tgt_der = generate_dummy_tgt()
        auth_der = generate_dummy_authenticator()
        print("\nGenerated random DER-encoded TGT and Authenticator blobs.")
    else:
        tgt_der = binascii.unhexlify(
            "3081a4310b1b0f505241495249452d464952452e4c4142310a1b066b726274677431820100" +
            "0480302e7b84aa3792a0a994cadc65878de812b9884d60309fd06b248f48b16f96ab11f40a89"
        )
        auth_der = binascii.unhexlify(
            "303e1b084761627269656c611b0f32303235303632393132333435365a0420aabbccddeeff" +
            "00112233445566778899aabbccddeeff0011223344556677"
        )
        print("\n[+] Using hardcoded DER-encoded values.")

    print("\nTGT DER (hex):")
    print(binascii.hexlify(tgt_der).decode())
    print("\nAuthenticator DER (hex):")
    print(binascii.hexlify(auth_der).decode())

    construct_ap_req(tgt_der, auth_der)


if __name__ == '__main__':
    main()
