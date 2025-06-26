def normalize_kerberos_principal(user_input: str, default_realm: str) -> str:
    """
    Verbosely normalize a user-provided logon string into a Kerberos principal name.
    Supports NT4-style (DOMAIN\\USER), UPN-style (user@realm), or bare usernames.
    """

    print("  --Kerberos Principal Normalization")
    print("    This process simulates how Windows prepares user identity")
    print("    for Kerberos authentication inside lsass.exe.")
    
    print(f"\n[+] Raw user input: '{user_input}'")
    user_input = user_input.strip()
    print(f"    ⤷ Stripped input: '{user_input}'")

    if "\\" in user_input:
        print("\n[*] Detected format: NT4-style → DOMAIN\\USERNAME")
        domain, username = user_input.split("\\", 1)
        print(f"    ⤷ DOMAIN  : '{domain}'")
        print(f"    ⤷ USERNAME: '{username}'")
        realm = domain.upper()
        print(f"    ⤷ Normalized Realm (UPPER): '{realm}'")
    elif "@" in user_input:
        print("\n[*] Detected format: Kerberos-style → USERNAME@REALM")
        username, realm = user_input.split("@", 1)
        print(f"    ⤷ USERNAME: '{username}'")
        print(f"    ⤷ REALM   : '{realm}'")
    else:
        print("\n[*] Detected format: Bare username only")
        username = user_input
        realm = default_realm.upper()
        print(f"    ⤷ Default Realm used: '{realm}'")

    # Case normalization
    username = username.strip().lower()
    realm = realm.strip().upper()

    print("\n[*] Final Normalization Step:")
    print(f"    ⤷ Normalized Username (lowercase): '{username}'")
    print(f"    ⤷ Normalized Realm    (UPPERCASE): '{realm}'")

    principal = f"{username}@{realm}"
    print(f"\n[+] Final Kerberos Principal Name: {principal}")
    return principal


# === Example Usage ===
if __name__ == "__main__":
    default_realm = "PRAIRIE-FIRE.LAB"

    inputs = [
        "Gabriela",
        "PRAIRIE-FIRE\\Gabriela",
        "gabriela@prairie-fire.lab",
        "  prairie-fire\\Gabriela  ",
        "gabriela@PRAIRIE-FIRE.lab"
    ]

    for raw in inputs:
        normalize_kerberos_principal(raw, default_realm)
