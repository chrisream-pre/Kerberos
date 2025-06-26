from datetime import datetime, timedelta, UTC
import base64
import json
from pprint import pprint

print("\n1) Define Kerberos realm and principal names.")
realm = "PRAIRIE-FIRE.LAB"
client_principal = "gabriela"
server_principal = "krbtgt/PRAIRIE-FIRE.LAB"
print(f"   - Realm: {realm}")
print(f"   - Client Principal: {client_principal}")
print(f"   - Server Principal: {server_principal}")

print("\n2) Create a symmetric session key for communication with the TGS.")
encryption_type = 18  # AES256-CTS-HMAC-SHA1-96
session_key = b'\x01' * 32  # 256-bit dummy session key
session_key_b64 = base64.b64encode(session_key).decode()
print(f"   - Encryption Type: {encryption_type} (AES256)")
print(f"   - Session Key (Raw): {session_key.hex()}")
print(f"   - Session Key (Base64): {session_key_b64}")

print("\n3) Generate timestamp metadata for ticket lifecycle.")
authtime = datetime.now(UTC)
starttime = authtime
endtime = authtime + timedelta(hours=10)
renew_till = authtime + timedelta(days=7)
print(f"   - Auth Time: {authtime.isoformat()}")
print(f"   - Start Time: {starttime.isoformat()}")
print(f"   - End Time: {endtime.isoformat()}")
print(f"   - Renew Till: {renew_till.isoformat()}")

print("\n4) Simulate an encrypted Ticket Granting Ticket (TGT) blob.")
ticket_blob_raw = b"DummyEncryptedTicketData"
ticket_blob_b64 = base64.b64encode(ticket_blob_raw).decode()
print(f"   - Encrypted Ticket Data (Raw): {ticket_blob_raw}")
print(f"   - Encrypted Ticket Data (Base64): {ticket_blob_b64}")

print("\n5) Assemble the .ccache entry with all necessary fields.\n")
ccache_entry = {
    "principal": {
        "client": f"{client_principal}@{realm}",
        "server": server_principal
    },
    "session_key": {
        "enctype": encryption_type,
        "key": session_key_b64
    },
    "ticket": ticket_blob_b64,
    "flags": ["forwardable", "renewable", "pre_authent"],
    "authtime": authtime.isoformat(),
    "starttime": starttime.isoformat(),
    "endtime": endtime.isoformat(),
    "renew_till": renew_till.isoformat(),
    "realm": realm
}

pprint(ccache_entry)

print("\n6) Serialize ccache entry as a base64-encoded JSON blob (simulated .ccache).")
json_blob = json.dumps(ccache_entry).encode("utf-8")
ccache_simulated_b64 = base64.b64encode(json_blob).decode()
print("\n--- Simulated .ccache (Base64 Encoded) ---\n")
print(ccache_simulated_b64)
