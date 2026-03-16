import os
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from .base_provider import CryptoProvider
from .security_utils import NonceTracker

class Ed25519Provider(CryptoProvider):
    def __init__(self, role: str):
        self.role = role
        self.nonce_tracker = NonceTracker()
        
        if self.role == "publisher":
            key_path = "keys/publisher_private.bin"
            if not os.path.exists(key_path):
                raise FileNotFoundError(f"Missing {key_path}. Run generate_asymmetric_keys.py first.")
            with open(key_path, "rb") as f:
                self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
                
        elif self.role == "subscriber":
            key_path = "keys/subscriber_public.bin"
            if not os.path.exists(key_path):
                raise FileNotFoundError(f"Missing {key_path}. Run generate_asymmetric_keys.py first.")
            with open(key_path, "rb") as f:
                self.public_key = ed25519.Ed25519PublicKey.from_public_bytes(f.read())
        else:
            raise ValueError("Role must be 'publisher' or 'subscriber'")

    def get_algo_name(self) -> str:
        return "Ed25519 Digital Signature + Nonce Tracking (Byte Stream)"

    def protect(self, raw_message: bytes) -> tuple[bytes, dict]:
        if self.role != "publisher":
            raise PermissionError("Only the publisher can sign messages.")
            
        t_start_total = time.perf_counter()

        # 1. Generate unique nonce
        t0 = time.perf_counter()
        nonce = os.urandom(16)
        t_nonce = (time.perf_counter() - t0) * 1000
        
        # 2. Cryptographic Binding (Sign the message AND the nonce together)
        data_to_sign = raw_message + nonce
        
        # 3. Generate Digital Signature
        t1 = time.perf_counter()
        signature = self.private_key.sign(data_to_sign)
        t_sign = (time.perf_counter() - t1) * 1000

        t_total_crypto = (time.perf_counter() - t_start_total) * 1000

        # ---------------------------------------------------------
        # PURE BYTE STREAM: [NONCE (16)] + [SIGNATURE (64)] + [PLAINTEXT]
        # ---------------------------------------------------------
        secure_stream = nonce + signature + raw_message
        
        metrics = {
            "pub_nonce_ms": t_nonce,
            "pub_sign_ms": t_sign,
            "pub_total_crypto_ms": t_total_crypto
        }
        return secure_stream, metrics

    def verify(self, secure_stream: bytes) -> tuple[bytes, dict]:
        if self.role != "subscriber":
            raise PermissionError("Only the subscriber can verify messages in this setup.")

        # ---------------------------------------------------------
        # SLICING: Ed25519 Nonce is 16 bytes, Signature is exactly 64 bytes
        # ---------------------------------------------------------
        nonce = secure_stream[:16]
        signature = secure_stream[16:80]
        raw_message = secure_stream[80:]
        
        data_to_verify = raw_message + nonce
        metrics = {}
        
        t_start_total = time.perf_counter()

        # 1. Nonce Tracking (O(1) Replay Protection)
        t0 = time.perf_counter()
        if not self.nonce_tracker.check_and_add(nonce):
            raise ValueError("Replay Attack Detected! This exact message was already processed.")
        metrics["sub_nonce_check_ms"] = (time.perf_counter() - t0) * 1000

        # 2. Signature Authentication
        t1 = time.perf_counter()
        try:
            self.public_key.verify(signature, data_to_verify)
            metrics["sub_verify_ms"] = (time.perf_counter() - t1) * 1000
        except Exception:
            raise ValueError("Digital Signature Invalid! Message tampered or source unverified.")

        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000
        
        return raw_message, metrics