import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_static_keys():
    print("Generating static Ed25519 key pair...")
    os.makedirs("keys", exist_ok=True)

    # 1. Generate the Master Private Key (Stays strictly on the Publisher)
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 2. Derive the Public Key (Shared with all Subscribers)
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # 3. Save them to persistent storage
    with open("keys/publisher_private.bin", "wb") as f:
        f.write(private_bytes)
    with open("keys/subscriber_public.bin", "wb") as f:
        f.write(public_bytes)

    print("Success! Keys saved to the 'keys/' directory:")
    print(" -> keys/publisher_private.bin (Publisher's Identity)")
    print(" -> keys/subscriber_public.bin (Subscribers' Verification Key)")

if __name__ == "__main__":
    generate_static_keys()