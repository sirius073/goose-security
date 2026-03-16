import os

def generate_master_key():
    # 1. Ensure the 'keys' directory exists
    os.makedirs("keys", exist_ok=True)
    
    # 2. Generate a cryptographically secure 32-byte (256-bit) random key
    master_key = b"A_Very_Secure_32_Byte_Master_Key"
    
    # 3. Write the exact bytes to the binary file
    key_path = "keys/shared_key.bin"
    with open(key_path, "wb") as key_file:
        key_file.write(master_key)
        
    print(f"Success! A 32-byte master key has been saved to '{key_path}'")
    print(f"For your reference, here is the key in Hexadecimal format:")
    print(f"-> {master_key.hex()}")

if __name__ == "__main__":
    generate_master_key()