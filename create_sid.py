import random

def prompt_identifier_authority():
    authorities = {
        "0": "Null Authority",
        "1": "World Authority",
        "2": "Local Authority",
        "3": "Creator Authority",
        "4": "Non-unique Authority",
        "5": "NT Authority",
        "6": "Site Server Authority"
    }
    print("\nIdentifier Authorities:")
    for key, val in authorities.items():
        print(f"    {key} - {val}")
    while True:
        choice = input("Choose Identifier Authority (number): ")
        if choice in authorities:
            print(f"    Selected: {authorities[choice]} ({choice})")
            return int(choice)
        else:
            print("    Invalid choice. Try again.")

def prompt_subauthority_0():
    known_values = {
        "0": "Null SID (subauthority 0)",
        "1": "Built-in SID",
        "2": "Local SID",
        "21": "Domain or Local Machine SID"
    }
    print("\nSubAuthority[0] Options:")
    for key, val in known_values.items():
        print(f"    {key} - {val}")
    while True:
        choice = input("Choose SubAuthority[0]: ")
        if choice.isdigit():
            print(f"    Selected: {choice}")
            return int(choice)
        else:
            print("    Invalid input. Try a numeric value.")

def prompt_rid():
    well_known = {
        "500": "Administrator",
        "501": "Guest",
        "512": "Domain Admins",
        "513": "Domain Users",
        "514": "Domain Guests",
        "515": "Domain Computers",
        "519": "Enterprise Admins"
    }
    print("\n[+] Well-Known RIDs:")
    for key, val in well_known.items():
        print(f"    {key} - {val}")
    print("    XXX - Custom RID (type manually)")

    choice = input(" Choose or type a RID: ")
    if choice.isdigit():
        print(f"    Selected RID: {choice}")
        return int(choice)
    else:
        print("    Invalid input. Must be a number.")
        return prompt_rid()

def generate_random_subauthorities():
    print("\nGenerating 3 random 32-bit SubAuthorities for our unique Domain identifier...")
    subs = [random.randint(100000000, 4000000000) for _ in range(3)]
    for i, s in enumerate(subs):
        print(f"    SubAuthority[{i+1}]: {s}")
    return subs

def build_sid():
    print("\nSID Builder")
    revision = 1
    id_auth = prompt_identifier_authority()
    subauth0 = prompt_subauthority_0()
    domain_subauths = generate_random_subauthorities()
    rid = prompt_rid()

    subauth_list = [subauth0] + domain_subauths + [rid]
    sid = f"S-{revision}-{id_auth}-" + "-".join(str(sa) for sa in subauth_list)
    
    print("\nConstructed SID:")
    print(f"    {sid}")
    return sid

if __name__ == "__main__":
    build_sid()
