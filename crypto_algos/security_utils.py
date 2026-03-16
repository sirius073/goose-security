# File: crypto_algos/security_utils.py

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class NonceTracker:
    """
    Implements O(1) Replay Attack Prevention.
    Maintains a set of used nonces to guarantee each message is unique.
    """
    def __init__(self):
        self.used_nonces = set()

    def check_and_add(self, nonce: bytes) -> bool:
        """Returns False if nonce is already used (Replay Attack), True otherwise."""
        if nonce in self.used_nonces:
            return False
        self.used_nonces.add(nonce)
        return True

class DynamicKeyManager:
    """
    Implements HKDF with SHA-256 to derive a unique 256-bit key per message 
    using a static master key and a dynamic random salt.
    """
    def __init__(self, master_key: bytes):
        self.master_key = master_key

    def derive_key(self, salt: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 256 bits required for ChaCha20
            salt=salt,
            info=b"GOOSE_message_key_derivation",
        )
        return hkdf.derive(self.master_key)