import os
import time
import ctypes
import importlib
from ctypes import POINTER, byref, c_int, c_ubyte, c_ulonglong
from .base_provider import CryptoProvider
from .security_utils import NonceTracker, DynamicKeyManager

try:
    _ascon_py = importlib.import_module("ascon")
except Exception:
    _ascon_py = None


class _AsconCLib:
    KEY_LEN = 16
    NONCE_LEN = 16
    TAG_LEN = 16

    def __init__(self) -> None:
        self._lib = self._load_library()
        self._encrypt = self._resolve_symbol(["crypto_aead_encrypt"])
        self._decrypt = self._resolve_symbol(["crypto_aead_decrypt"])
        self._configure_signatures()

    def _load_library(self):
        explicit_path = os.getenv("ASCON_C_LIB")
        candidate_paths = []

        if explicit_path:
            candidate_paths.append(explicit_path)

        candidate_paths.extend([
            "ascon.dll",
            "libascon.dll",
            "ascon-c.dll",
            "libascon-c.dll",
        ])

        errors = []
        for path in candidate_paths:
            try:
                return ctypes.CDLL(path)
            except OSError as exc:
                errors.append(f"{path}: {exc}")

        detail = " | ".join(errors) if errors else "No candidates tried"
        raise RuntimeError(
            "Unable to load ascon-c shared library. "
            "Set ASCON_C_LIB to your compiled DLL path (e.g., C:\\path\\to\\libascon.dll). "
            f"Load attempts: {detail}"
        )

    def _resolve_symbol(self, candidates: list[str]):
        for symbol_name in candidates:
            symbol = getattr(self._lib, symbol_name, None)
            if symbol is not None:
                return symbol
        raise RuntimeError(f"ascon-c symbol not found. Tried: {', '.join(candidates)}")

    def _configure_signatures(self) -> None:
        self._encrypt.argtypes = [
            POINTER(c_ubyte),
            POINTER(c_ulonglong),
            POINTER(c_ubyte),
            c_ulonglong,
            POINTER(c_ubyte),
            c_ulonglong,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
        ]
        self._encrypt.restype = c_int

        self._decrypt.argtypes = [
            POINTER(c_ubyte),
            POINTER(c_ulonglong),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_ulonglong,
            POINTER(c_ubyte),
            c_ulonglong,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
        ]
        self._decrypt.restype = c_int

    @staticmethod
    def _to_u8_ptr(data: bytes):
        if not data:
            return None
        return (c_ubyte * len(data)).from_buffer_copy(data)

    def encrypt(self, key: bytes, nonce: bytes, associated_data: bytes, plaintext: bytes) -> bytes:
        if len(key) != self.KEY_LEN:
            raise ValueError(f"Invalid ASCON-128a key length: expected {self.KEY_LEN}, got {len(key)}")
        if len(nonce) != self.NONCE_LEN:
            raise ValueError(f"Invalid ASCON-128a nonce length: expected {self.NONCE_LEN}, got {len(nonce)}")

        max_ciphertext_len = len(plaintext) + self.TAG_LEN
        ciphertext_buffer = (c_ubyte * max_ciphertext_len)()
        ciphertext_len = c_ulonglong(0)

        key_ptr = self._to_u8_ptr(key)
        nonce_ptr = self._to_u8_ptr(nonce)
        ad_ptr = self._to_u8_ptr(associated_data)
        plaintext_ptr = self._to_u8_ptr(plaintext)

        rc = self._encrypt(
            ciphertext_buffer,
            byref(ciphertext_len),
            plaintext_ptr,
            c_ulonglong(len(plaintext)),
            ad_ptr,
            c_ulonglong(len(associated_data)),
            None,
            nonce_ptr,
            key_ptr,
        )
        if rc != 0:
            raise ValueError(f"ascon-c encryption failed with code {rc}")

        return bytes(ciphertext_buffer[:ciphertext_len.value])

    def decrypt(self, key: bytes, nonce: bytes, associated_data: bytes, ciphertext: bytes) -> bytes:
        if len(key) != self.KEY_LEN:
            raise ValueError(f"Invalid ASCON-128a key length: expected {self.KEY_LEN}, got {len(key)}")
        if len(nonce) != self.NONCE_LEN:
            raise ValueError(f"Invalid ASCON-128a nonce length: expected {self.NONCE_LEN}, got {len(nonce)}")
        if len(ciphertext) < self.TAG_LEN:
            raise ValueError("Invalid ciphertext length for ASCON-128a")

        plaintext_buffer = (c_ubyte * len(ciphertext))()
        plaintext_len = c_ulonglong(0)

        key_ptr = self._to_u8_ptr(key)
        nonce_ptr = self._to_u8_ptr(nonce)
        ad_ptr = self._to_u8_ptr(associated_data)
        ciphertext_ptr = self._to_u8_ptr(ciphertext)

        rc = self._decrypt(
            plaintext_buffer,
            byref(plaintext_len),
            None,
            ciphertext_ptr,
            c_ulonglong(len(ciphertext)),
            ad_ptr,
            c_ulonglong(len(associated_data)),
            nonce_ptr,
            key_ptr,
        )
        if rc != 0:
            raise ValueError("Data Tampering Detected! ASCON authentication failed.")

        return bytes(plaintext_buffer[:plaintext_len.value])


class _AsconPyLib:
    KEY_LEN = 16
    NONCE_LEN = 16

    def __init__(self) -> None:
        if _ascon_py is None:
            raise RuntimeError(
                "Python 'ascon' package is not available. Install it or switch backend to 'c'."
            )

    def encrypt(self, key: bytes, nonce: bytes, associated_data: bytes, plaintext: bytes) -> bytes:
        if len(key) != self.KEY_LEN:
            raise ValueError(f"Invalid ASCON-128a key length: expected {self.KEY_LEN}, got {len(key)}")
        if len(nonce) != self.NONCE_LEN:
            raise ValueError(f"Invalid ASCON-128a nonce length: expected {self.NONCE_LEN}, got {len(nonce)}")
        return _ascon_py.encrypt(key, nonce, associated_data, plaintext, "Ascon-128a")

    def decrypt(self, key: bytes, nonce: bytes, associated_data: bytes, ciphertext: bytes) -> bytes:
        if len(key) != self.KEY_LEN:
            raise ValueError(f"Invalid ASCON-128a key length: expected {self.KEY_LEN}, got {len(key)}")
        if len(nonce) != self.NONCE_LEN:
            raise ValueError(f"Invalid ASCON-128a nonce length: expected {self.NONCE_LEN}, got {len(nonce)}")
        raw_message = _ascon_py.decrypt(key, nonce, associated_data, ciphertext, "Ascon-128a")
        if raw_message is None:
            raise ValueError("Data Tampering Detected! ASCON authentication failed.")
        return raw_message

class Ascon128aProvider(CryptoProvider):
    def __init__(self, master_shared_key: bytes, backend: str | None = None):
        self.key_manager = DynamicKeyManager(master_shared_key)
        self.nonce_tracker = NonceTracker()
        selected_backend = (backend or os.getenv("ASCON_BACKEND", "python")).strip().lower()

        if selected_backend in {"python", "py", "legacy"}:
            self._backend_name = "python"
            self._ascon = _AsconPyLib()
        elif selected_backend in {"c", "ascon-c", "asconc"}:
            self._backend_name = "c"
            self._ascon = _AsconCLib()
        else:
            raise ValueError(
                f"Unsupported ASCON backend '{selected_backend}'. Use 'python' or 'c'."
            )

    def get_algo_name(self) -> str:
        if self._backend_name == "python":
            return "ASCON-128a (Python ascon) (Byte Stream)"
        return "ASCON-128a (ascon-c) (Byte Stream)"

    def protect(self, raw_message: bytes) -> tuple[bytes, dict]:
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
        ciphertext = self._ascon.encrypt(dynamic_key, nonce, b"", raw_message)
        t_encrypt = (time.perf_counter() - t2) * 1000
        t_total_encrypt = (time.perf_counter() - t_start_total) * 1000

        # ---------------------------------------------------------
        # PURE BYTE STREAM: [SALT (32)] + [NONCE (16)] + [CIPHERTEXT + TAG]
        # ---------------------------------------------------------
        secure_stream = salt + nonce + ciphertext

        metrics = {
            "pub_key_deriv_ms": t_key_deriv,
            "pub_nonce_ms": t_nonce,
            "pub_encrypt_ms": t_encrypt,
            "pub_total_crypto_ms": t_total_encrypt
        }
        return secure_stream, metrics

    def verify(self, secure_stream: bytes) -> tuple[bytes, dict]:
        # ---------------------------------------------------------
        # SLICING: ASCON uses a 16-byte nonce, so offset is 32 -> 48
        # ---------------------------------------------------------
        salt = secure_stream[:32]
        nonce = secure_stream[32:48]
        ciphertext = secure_stream[48:]
        
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
            raw_message = self._ascon.decrypt(dynamic_key, nonce, b"", ciphertext)
        except Exception:
            raise ValueError("Data Tampering Detected! ASCON authentication failed.")
            
        metrics["sub_decrypt_ms"] = (time.perf_counter() - t2) * 1000
        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000

        return raw_message, metrics