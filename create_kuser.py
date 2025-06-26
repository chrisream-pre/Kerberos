import hashlib
import binascii

def derive_kerberos_key(username: str, realm: str, password: str, iterations: int = 4096, key_length: int = 32):

    print("\n Starting Kerberos Key Derivation")
    print("    Kerberos encryption type: AES256-CTS-HMAC-SHA1-96 (etype 18)")
    print("    PBKDF2 with HMAC-SHA1, 4096 iterations, 32-byte output\n")

    print(f" Input Parameters:")
    print(f"    Username: {username}")
    print(f"    Realm   : {realm}")
    print(f"    Password: {password}\n")

    # Normalize inputs
    normalized_username = username.lower()
    normalized_realm = realm.upper()
    print(" Normalized:")
    print(f"    username → {normalized_username}")
    print(f"    realm    → {normalized_realm}\n")

    # Kerberos salt = UPPERCASE_REALM + lowercase_username
    salt = normalized_realm + normalized_username
    print(" Salt Construction:")
    print(f"    salt = realm.upper() + username.lower()")
    print(f"    salt = {salt}")
    print(f"    Salt (hex): {salt.encode('utf-8').hex()}\n")

    print(" Deriving key using PBKDF2-HMAC-SHA1...")
    key = hashlib.pbkdf2_hmac(
        hash_name='sha1',
        password=password.encode('utf-8'),
        salt=salt.encode('utf-8'),
        iterations=iterations,
        dklen=key_length
    )
    print("     PBKDF2 complete.")
    print(f"    Derived Key (raw): {key}")
    print(f"    Derived Key (hex): {binascii.hexlify(key).decode('ascii')}\n")

    return binascii.hexlify(key).decode('ascii')


# === Example Usage ===
if __name__ == "__main__":
    username = "gabriela"
    realm = "PRAIRIE-FIRE.LAB"
    password = "P@ssw0rd12!@"

    print("Kerberos AES256 Key Derivation")
    derived_key = derive_kerberos_key(username, realm, password)
    print(f"[+] Final Output:\n    Kuser for {username}@{realm}:\n    {derived_key}")
