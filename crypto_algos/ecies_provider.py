import os
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .base_provider import CryptoProvider
from .security_utils import NonceTracker

class ECIESProvider(CryptoProvider):
    def __init__(self, role: str):
        self.role = role
        self.nonce_tracker = NonceTracker()
        
        if self.role == "publisher":
            # Publisher loads the public key to ENCRYPT the data
            with open("keys/sub_encrypt_public.bin", "rb") as f:
                self.peer_public_key = x25519.X25519PublicKey.from_public_bytes(f.read())
        elif self.role == "subscriber":
            # Subscriber loads the private key to DECRYPT the data
            with open("keys/sub_decrypt_private.bin", "rb") as f:
                self.private_key = x25519.X25519PrivateKey.from_private_bytes(f.read())

    def get_algo_name(self) -> str:
        return "ECIES (X25519 Asymmetric Encryption)"

    def protect(self, raw_message: bytes) -> dict:
        t_start_total = time.perf_counter()
        
        # 1. Asymmetric Math & Key Derivation
        t0 = time.perf_counter()
        ephemeral_private_key = x25519.X25519PrivateKey.generate()
        ephemeral_public_key = ephemeral_private_key.public_key()
        shared_secret = ephemeral_private_key.exchange(self.peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecies-goose"
        ).derive(shared_secret)
        t_key_math = (time.perf_counter() - t0) * 1000
        
        # 2. Nonce Generation
        t1 = time.perf_counter()
        nonce = os.urandom(12)
        t_nonce = (time.perf_counter() - t1) * 1000
        
        # 3. Symmetric Encryption
        t2 = time.perf_counter()
        chacha = ChaCha20Poly1305(derived_key)
        ciphertext = chacha.encrypt(nonce, raw_message, associated_data=None)
        t_encrypt = (time.perf_counter() - t2) * 1000

        t_total_encrypt = (time.perf_counter() - t_start_total) * 1000

        # We must send our temporary public key so the subscriber can do the reverse math
        ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        payload = {
            "algo": self.get_algo_name(),
            "ephemeral_pub": ephemeral_pub_bytes.hex(),
            "nonce": nonce.hex(),
            "data": ciphertext.hex(),
        }
        metrics = {
            "pub_key_deriv_ms": t_key_math,
            "pub_nonce_ms": t_nonce,
            "pub_encrypt_ms": t_encrypt,
            "pub_total_crypto_ms": t_total_encrypt
        }
        return payload, metrics

    def verify(self, payload: dict) -> tuple[bytes, dict]:
        ephemeral_pub_bytes = bytes.fromhex(payload["ephemeral_pub"])
        nonce = bytes.fromhex(payload["nonce"])
        ciphertext = bytes.fromhex(payload["data"])
        
        metrics = {}
        t_start_total = time.perf_counter()

        # 1. Replay Protection / Nonce Checking
        t0 = time.perf_counter()
        if not self.nonce_tracker.check_and_add(nonce):
            raise ValueError("Replay Attack Detected!")
        metrics["sub_nonce_check_ms"] = (time.perf_counter() - t0) * 1000

        # 2. Asymmetric Math & Key Derivation
        t1 = time.perf_counter()
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        shared_secret = self.private_key.exchange(ephemeral_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecies-goose"
        ).derive(shared_secret)
        metrics["sub_key_deriv_ms"] = (time.perf_counter() - t1) * 1000
        
        # 3. Symmetric Decryption
        t2 = time.perf_counter()
        chacha = ChaCha20Poly1305(derived_key)
        try:
            raw_message = chacha.decrypt(nonce, ciphertext, associated_data=None)
        except Exception:
            raise ValueError("Asymmetric Decryption Failed! Data tampered.")
        metrics["sub_decrypt_ms"] = (time.perf_counter() - t2) * 1000
            
        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000
        
        return raw_message, metrics