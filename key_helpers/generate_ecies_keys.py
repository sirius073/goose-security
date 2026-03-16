import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

def generate_ecies_keys():
    print("Generating static X25519 keys for Asymmetric Encryption...")
    os.makedirs("keys", exist_ok=True)

    # In Asymmetric Encryption, the SUBSCRIBER holds the Private Key to decrypt
    # The PUBLISHER uses the Subscriber's Public Key to encrypt
    subscriber_private_key = x25519.X25519PrivateKey.generate()
    subscriber_public_key = subscriber_private_key.public_key()

    priv_bytes = subscriber_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = subscriber_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    with open("keys/sub_decrypt_private.bin", "wb") as f: f.write(priv_bytes)
    with open("keys/sub_encrypt_public.bin", "wb") as f: f.write(pub_bytes)

    print("Success! Keys saved:")
    print(" -> keys/sub_encrypt_public.bin (Publisher uses this to ENCRYPT)")
    print(" -> keys/sub_decrypt_private.bin (Subscriber uses this to DECRYPT)")

if __name__ == "__main__":
    generate_ecies_keys()