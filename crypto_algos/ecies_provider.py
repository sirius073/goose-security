import os
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .base_provider import CryptoProvider
from .security_utils import GooseReplayTracker, extract_goose_state_numbers

class ECIESProvider(CryptoProvider):
    def __init__(self, role: str):
        self.role = role
        self.replay_tracker = GooseReplayTracker()
        self.boot_id = os.urandom(4)
        
        if self.role == "publisher":
            # Publisher loads the public key to ENCRYPT the data
            with open("keys/sub_encrypt_public.bin", "rb") as f:
                self.peer_public_key = x25519.X25519PublicKey.from_public_bytes(f.read())
        elif self.role == "subscriber":
            # Subscriber loads the private key to DECRYPT the data
            with open("keys/sub_decrypt_private.bin", "rb") as f:
                self.private_key = x25519.X25519PrivateKey.from_private_bytes(f.read())
        
        # Cache standard hash instance
        self.hash_algo = hashes.SHA256()

    def get_algo_name(self) -> str:
        return "ECIES (X25519 Asymmetric Encryption) (Byte Stream)"

    def protect(self, raw_message: bytes) -> tuple[bytes, dict]:
        t_start_total = time.perf_counter()
        
        # 1. Asymmetric Math & Key Derivation
        t0 = time.perf_counter()
        ephemeral_private_key = x25519.X25519PrivateKey.generate()
        ephemeral_public_key = ephemeral_private_key.public_key()
        shared_secret = ephemeral_private_key.exchange(self.peer_public_key)
        derived_key = HKDF(
            algorithm=self.hash_algo, length=32, salt=None, info=b"ecies-goose"
        ).derive(shared_secret)
        t_key_math = (time.perf_counter() - t0) * 1000
        
        st_num, sq_num = extract_goose_state_numbers(raw_message)
        nonce = self.boot_id + st_num.to_bytes(4, "big") + sq_num.to_bytes(4, "big")
        
        # Get ephemeral public bytes BEFORE encryption to use as Associated Data
        ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        
        # Group the unencrypted header data
        header_data = nonce + ephemeral_pub_bytes
        
        # 3. Symmetric Encryption with Associated Data (AAD)
        t2 = time.perf_counter()
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, raw_message, associated_data=header_data)
        t_encrypt = (time.perf_counter() - t2) * 1000

        t_total_encrypt = (time.perf_counter() - t_start_total) * 1000
        
        # ---------------------------------------------------------
        # PURE BYTE STREAM: [NONCE (12)] + [PUB_KEY (32)] + [CIPHERTEXT]
        # ---------------------------------------------------------
        secure_stream = header_data + ciphertext
        
        metrics = {
            "pub_key_deriv_ms": t_key_math,
            "pub_encrypt_ms": t_encrypt,
            "pub_total_crypto_ms": t_total_encrypt
        }
        return secure_stream, metrics

    def verify(self, secure_stream: bytes) -> tuple[bytes, dict]:
        # ---------------------------------------------------------
        # SLICING: [NONCE (12)] + [X25519 PUB_KEY (32)] + [CIPHERTEXT]
        # ---------------------------------------------------------
        header_data = secure_stream[:44]

        nonce = secure_stream[:12]
        boot_id = nonce[:4]
        st_num = int.from_bytes(nonce[4:8], "big")
        sq_num = int.from_bytes(nonce[8:12], "big")
        ephemeral_pub_bytes = secure_stream[12:44]
        ciphertext = secure_stream[44:]
        
        metrics = {}
        t_start_total = time.perf_counter()

        # 1. Replay Protection / sqNum Checking
        t0 = time.perf_counter()
        if not self.replay_tracker.is_acceptable(boot_id, st_num, sq_num):
            raise ValueError(
                f"Replay Attack! boot_id={boot_id.hex()} stNum={st_num} sqNum={sq_num}"
            )
        metrics["sub_replay_check_ms"] = (time.perf_counter() - t0) * 1000

        # 2. Asymmetric Math & Key Derivation
        t1 = time.perf_counter()
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        shared_secret = self.private_key.exchange(ephemeral_public_key)
        derived_key = HKDF(
            algorithm=self.hash_algo, length=32, salt=None, info=b"ecies-goose"
        ).derive(shared_secret)
        metrics["sub_key_deriv_ms"] = (time.perf_counter() - t1) * 1000
        
        # 3. Symmetric Decryption with Associated Data (AAD)
        t2 = time.perf_counter()
        aesgcm = AESGCM(derived_key)
        try:
            raw_message = aesgcm.decrypt(nonce, ciphertext, associated_data=header_data)
        except Exception:
            raise ValueError("Asymmetric Decryption Failed! Data tampered.")

        self.replay_tracker.commit(boot_id, st_num, sq_num)

        metrics["sub_decrypt_ms"] = (time.perf_counter() - t2) * 1000
            
        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000
        
        return raw_message, metrics