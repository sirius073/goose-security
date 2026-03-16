import os
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .base_provider import CryptoProvider
from .security_utils import NonceTracker, DynamicKeyManager

class ChaCha20Provider(CryptoProvider):
    def __init__(self, master_shared_key: bytes):
        # Initialize the decoupled security mechanisms
        self.key_manager = DynamicKeyManager(master_shared_key)
        self.nonce_tracker = NonceTracker()

    def get_algo_name(self) -> str:
        return "ChaCha20-Poly1305 (AEAD) + Dynamic Keys + Nonce Tracking"

    def protect(self, raw_message: bytes) -> dict:
        """Publisher side: Generates salt/nonce, derives key, encrypts, and measures time."""
        t_start_total = time.perf_counter()
        
        # 1. Dynamic Key Derivation
        t0 = time.perf_counter()
        salt = os.urandom(32)
        dynamic_key = self.key_manager.derive_key(salt)
        t_key_gen = (time.perf_counter() - t0) * 1000

        # 2. Nonce Generation
        t1 = time.perf_counter()
        nonce = os.urandom(12) # 96-bit nonce
        t_nonce = (time.perf_counter() - t1) * 1000

        # 3. ChaCha20 Encryption & Poly1305 MAC Generation
        t2 = time.perf_counter()
        chacha = ChaCha20Poly1305(dynamic_key)
        ciphertext = chacha.encrypt(nonce, raw_message, associated_data=None)
        t_encrypt = (time.perf_counter() - t2) * 1000
        
        t_total_crypto = (time.perf_counter() - t_start_total) * 1000
        payload = {
            "algo": self.get_algo_name(),
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "data": ciphertext.hex(),
        }
        metrics = {
            "pub_key_deriv_ms": t_key_gen,
            "pub_nonce_ms": t_nonce,
            "pub_encrypt_ms": t_encrypt,
            "pub_total_crypto_ms": t_total_crypto
        }
        return payload, metrics

    def verify(self, payload: dict) -> tuple[bytes, dict]:
        """Subscriber side: Verifies nonce, derives key, authenticates MAC, decrypts."""
        salt = bytes.fromhex(payload["salt"])
        nonce = bytes.fromhex(payload["nonce"])
        ciphertext = bytes.fromhex(payload["data"])
        
        metrics = {}
        t_start_total = time.perf_counter()

        # 1. Replay Attack Prevention (Nonce Tracking)
        t0 = time.perf_counter()
        if not self.nonce_tracker.check_and_add(nonce):
            raise ValueError("Replay Attack Detected! Nonce already used in a previous GOOSE message.")
        metrics["sub_nonce_check_ms"] = (time.perf_counter() - t0) * 1000

        # 2. Dynamic Key Derivation
        t1 = time.perf_counter()
        dynamic_key = self.key_manager.derive_key(salt)
        metrics["sub_key_deriv_ms"] = (time.perf_counter() - t1) * 1000

        # 3. Decryption & Poly1305 Authenticity Check
        t2 = time.perf_counter()
        chacha = ChaCha20Poly1305(dynamic_key)
        try:
            # If the MAC tag fails or ciphertext is tampered with, this throws an exception
            raw_message = chacha.decrypt(nonce, ciphertext, associated_data=None)
        except Exception:
            raise ValueError("Data Tampering Detected! Poly1305 MAC verification failed.")
            
        metrics["sub_decrypt_ms"] = (time.perf_counter() - t2) * 1000

        # Calculate Total Cryptographic Latency (Must be low to meet 10ms GOOSE standard)
        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000

        return raw_message, metrics