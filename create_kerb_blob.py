import ctypes

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer", ctypes.c_void_p)
    ]

# KERB_INTERACTIVE_LOGON structure
class KERB_INTERACTIVE_LOGON(ctypes.Structure):
    _fields_ = [
        ("MessageType", ctypes.c_ulong),  # KerbInteractiveLogon = 0x02
        ("LogonDomainName", UNICODE_STRING),
        ("UserName", UNICODE_STRING),
        ("Password", UNICODE_STRING)
    ]

# Our user input
username = "Gabriela"
domain = "PRAIRIE-FIRE"
password = "P@ssw0rd12!@"

def create_unicode_string(value: str, label: str):
    print(f"\nEncoding {label}: \"{value}\"")
    encoded = value.encode('utf-16-le')
    print(f"    Encoded UTF-16LE ({len(encoded)} bytes): {encoded.hex()}")

    buffer = ctypes.create_string_buffer(encoded)
    print(f"    Allocated memory at: {ctypes.addressof(buffer):#010x}")

    us = UNICODE_STRING(
        Length=len(encoded),
        MaximumLength=len(encoded) + 2,  # add space for null-terminator
        Buffer=ctypes.cast(buffer, ctypes.c_void_p)
    )

    print(f"    UNICODE_STRING -> Length: {us.Length}, MaxLength: {us.MaximumLength}, Buffer: {us.Buffer:#010x}")
    return us, buffer

# Verbose field output
domain_str, domain_buf = create_unicode_string(domain, "Domain")
user_str, user_buf = create_unicode_string(username, "Username")
pass_str, pass_buf = create_unicode_string(password, "Password")

# Build the main structure
print("\nCreating KERB_INTERACTIVE_LOGON structure")
logon_struct = KERB_INTERACTIVE_LOGON()
logon_struct.MessageType = 0x02  # KerbInteractiveLogon
logon_struct.LogonDomainName = domain_str
logon_struct.UserName = user_str
logon_struct.Password = pass_str

print(f"    MessageType: {logon_struct.MessageType} (should be 0x02)")
print("    Structure size:", ctypes.sizeof(logon_struct), "bytes")

# Dump raw bytes of the structure
print("\nSerializing structure into memory")
raw_bytes = ctypes.string_at(ctypes.byref(logon_struct), ctypes.sizeof(logon_struct))

print("Serialized KERB_INTERACTIVE_LOGON bytes (hex):")
hex_dump = " ".join(f"{b:02x}" for b in raw_bytes)
print(f"    {hex_dump}")
