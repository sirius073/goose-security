import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .base_provider import CryptoProvider
from .security_utils import NonceTracker, DynamicKeyManager

class AESGCMProvider(CryptoProvider):
    def __init__(self, master_shared_key: bytes):
        # Initialize the decoupled security mechanisms
        self.key_manager = DynamicKeyManager(master_shared_key)
        self.nonce_tracker = NonceTracker()

    def get_algo_name(self) -> str:
        return "AES-256-GCM (AEAD) + Dynamic Keys + Nonce Tracking"

    def protect(self, raw_message: bytes) -> tuple[dict, dict]:
        """Publisher side: Generates salt/nonce, derives key, encrypts, and measures time."""
        t_start_total = time.perf_counter()
        
        # 1. Dynamic Key Derivation
        t0 = time.perf_counter()
        salt = os.urandom(32)
        # Assuming your key_manager outputs 32 bytes (256 bits) for AES-256
        dynamic_key = self.key_manager.derive_key(salt)[:32] 
        t_key_gen = (time.perf_counter() - t0) * 1000

        # 2. Nonce Generation
        t1 = time.perf_counter()
        # NIST recommends exactly 12 bytes (96 bits) for AES-GCM nonces
        nonce = os.urandom(12) 
        t_nonce = (time.perf_counter() - t1) * 1000

        # 3. AES-GCM Encryption & Authentication Tag Generation
        t2 = time.perf_counter()
        aesgcm = AESGCM(dynamic_key)
        # Like ASCON and ChaCha, encrypt() appends the 16-byte MAC tag to the end
        ciphertext = aesgcm.encrypt(nonce, raw_message, associated_data=None)
        t_encrypt = (time.perf_counter() - t2) * 1000
        
        t_total_crypto = (time.perf_counter() - t_start_total) * 1000
        
        # Lean Network Payload
        payload = {
            "algo": self.get_algo_name(),
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "data": ciphertext.hex(),
        }
        
        # Local Metrics (Not sent over the network)
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
        dynamic_key = self.key_manager.derive_key(salt)[:32]
        metrics["sub_key_deriv_ms"] = (time.perf_counter() - t1) * 1000

        # 3. Decryption & AES-GCM Authenticity Check
        t2 = time.perf_counter()
        aesgcm = AESGCM(dynamic_key)
        try:
            # Slices off the tag, verifies it, and unscrambles the data
            raw_message = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except Exception:
            raise ValueError("Data Tampering Detected! AES-GCM authentication tag failed.")
            
        metrics["sub_decrypt_ms"] = (time.perf_counter() - t2) * 1000

        # Calculate Total Cryptographic Latency
        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000

        return raw_message, metrics