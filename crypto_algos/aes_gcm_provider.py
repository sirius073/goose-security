import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .base_provider import CryptoProvider
from .security_utils import GooseReplayTracker, extract_goose_state_numbers

class AESGCMProvider(CryptoProvider):
    def __init__(self, master_shared_key: bytes):
        self.master_shared_key = master_shared_key[:32]
        self.replay_tracker = GooseReplayTracker()
        self.boot_id = os.urandom(4)
        self.aesgcm = AESGCM(self.master_shared_key)

    def get_algo_name(self) -> str:
        return "AES-256-GCM (AEAD) + GOOSE Nonce [BootID|stNum|sqNum] (Byte Stream)"

    def protect(self, raw_message: bytes) -> tuple[bytes, dict]:
        """Publisher side: Builds GOOSE nonce and encrypts with AES-GCM."""
        t_start_total = time.perf_counter()

        st_num, sq_num = extract_goose_state_numbers(raw_message)
        nonce = self.boot_id + st_num.to_bytes(4, "big") + sq_num.to_bytes(4, "big")

        # AES-GCM Encryption & Authentication Tag Generation
        t2 = time.perf_counter()
        ciphertext = self.aesgcm.encrypt(nonce, raw_message, associated_data=nonce)
        t_encrypt = (time.perf_counter() - t2) * 1000
        
        t_total_crypto = (time.perf_counter() - t_start_total) * 1000
        
        # ---------------------------------------------------------
        # Structure: [NONCE (12 bytes)] + [CIPHERTEXT + TAG]
        # ---------------------------------------------------------
        secure_stream = nonce + ciphertext
        
        # Local Metrics (Not sent over the network)
        metrics = {
            "pub_encrypt_ms": t_encrypt,
            "pub_total_crypto_ms": t_total_crypto
        }
        return secure_stream, metrics

    def verify(self, secure_stream: bytes) -> tuple[bytes, dict]:
        """Subscriber side: Verifies replay from nonce and decrypts."""
        
        # ---------------------------------------------------------
        # Byte slicing based on known fixed lengths
        # ---------------------------------------------------------
        nonce = secure_stream[:12]
        ciphertext = secure_stream[12:]
        boot_id = nonce[:4]
        st_num = int.from_bytes(nonce[4:8], "big")
        sq_num = int.from_bytes(nonce[8:12], "big")
        
        metrics = {}
        t_start_total = time.perf_counter()

        # 1. Replay Protection using Boot ID + stNum + sqNum
        t0 = time.perf_counter()
        if not self.replay_tracker.is_acceptable(boot_id, st_num, sq_num):
            raise ValueError(
                f"Replay Attack! boot_id={boot_id.hex()} stNum={st_num} sqNum={sq_num}"
            )
        metrics["sub_replay_check_ms"] = (time.perf_counter() - t0) * 1000

        # 2. Decryption & AES-GCM Authenticity Check
        t2 = time.perf_counter()
        try:
            raw_message = self.aesgcm.decrypt(nonce, ciphertext, associated_data=nonce)
        except Exception:
            raise ValueError("Data Tampering Detected! AES-GCM authentication tag failed.")

        self.replay_tracker.commit(boot_id, st_num, sq_num)
            
        metrics["sub_decrypt_ms"] = (time.perf_counter() - t2) * 1000

        # Calculate Total Cryptographic Latency
        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000

        return raw_message, metrics