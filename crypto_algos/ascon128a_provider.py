import os
import time
import ascon  
from .base_provider import CryptoProvider
from .security_utils import NonceTracker, DynamicKeyManager

class Ascon128aProvider(CryptoProvider):
    def __init__(self, master_shared_key: bytes):
        self.key_manager = DynamicKeyManager(master_shared_key)
        self.nonce_tracker = NonceTracker()

    def get_algo_name(self) -> str:
        return "ASCON-128a (NIST LWC Winner)"

    def protect(self, raw_message: bytes) -> dict:
        t_start_total = time.perf_counter()
        
        # 1. Salt Generation & Key Derivation
        t0 = time.perf_counter()
        salt = os.urandom(32)
        # ASCON-128a uses 128-bit keys (16 bytes)
        dynamic_key = self.key_manager.derive_key(salt)[:16] 
        t_key_deriv = (time.perf_counter() - t0) * 1000

        # 2. Nonce Generation
        t1 = time.perf_counter()
        nonce = os.urandom(16) 
        t_nonce = (time.perf_counter() - t1) * 1000
        
        # 3. ASCON Encryption
        t2 = time.perf_counter()
        
        ciphertext = ascon.encrypt(
            dynamic_key, 
            nonce, 
            b"", # Associated Data
            raw_message, 
            "Ascon-128a"
        )
        t_encrypt = (time.perf_counter() - t2) * 1000

        t_total_encrypt = (time.perf_counter() - t_start_total) * 1000

        payload = {
            "algo": self.get_algo_name(),
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "data": ciphertext.hex()
        }
        metrics = {
            "pub_key_deriv_ms": t_key_deriv,
                "pub_nonce_ms": t_nonce,
                "pub_encrypt_ms": t_encrypt,
                "pub_total_crypto_ms": t_total_encrypt
            }
        return payload, metrics

    def verify(self, payload: dict) -> tuple[bytes, dict]:
        salt = bytes.fromhex(payload["salt"])
        nonce = bytes.fromhex(payload["nonce"])
        ciphertext = bytes.fromhex(payload["data"])
        
        metrics = {}
        t_start_total = time.perf_counter()

        # 1. Replay Attack / Nonce Check
        t0 = time.perf_counter()
        if not self.nonce_tracker.check_and_add(nonce):
            raise ValueError("Replay Attack Detected!")
        metrics["sub_nonce_check_ms"] = (time.perf_counter() - t0) * 1000

        # 2. Key Derivation
        t1 = time.perf_counter()
        dynamic_key = self.key_manager.derive_key(salt)[:16]
        metrics["sub_key_deriv_ms"] = (time.perf_counter() - t1) * 1000

        # 3. ASCON Decryption & Authentication
        t2 = time.perf_counter()
        try:
            # FIX: Using ascon.decrypt
            raw_message = ascon.decrypt(
                dynamic_key, 
                nonce, 
                b"", 
                ciphertext, 
                "Ascon-128a"
            )
        except Exception:
            raise ValueError("Data Tampering Detected! ASCON authentication failed.")
            
        metrics["sub_decrypt_ms"] = (time.perf_counter() - t2) * 1000
        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000

        return raw_message, metrics