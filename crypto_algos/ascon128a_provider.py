import os
import time
import ctypes
import importlib
from ctypes import POINTER, byref, c_int, c_ubyte, c_ulonglong, c_char_p
from .base_provider import CryptoProvider
from .security_utils import GooseReplayTracker, extract_goose_state_numbers

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
            POINTER(c_ubyte), POINTER(c_ulonglong), 
            c_char_p, c_ulonglong,  # Plaintext
            c_char_p, c_ulonglong,  # Associated Data
            c_char_p,               # Secret (None for ASCON AEAD)
            c_char_p,               # Nonce
            c_char_p,               # Key
        ]
        self._encrypt.restype = c_int

        self._decrypt.argtypes = [
            POINTER(c_ubyte), POINTER(c_ulonglong), 
            c_char_p,               # Secret (None)
            c_char_p, c_ulonglong,  # Ciphertext
            c_char_p, c_ulonglong,  # Associated Data
            c_char_p,               # Nonce
            c_char_p,               # Key
        ]
        self._decrypt.restype = c_int

    def encrypt(self, key: bytes, nonce: bytes, associated_data: bytes, plaintext: bytes) -> bytes:
        if len(key) != self.KEY_LEN:
            raise ValueError(f"Invalid ASCON-128a key length: expected {self.KEY_LEN}, got {len(key)}")
        if len(nonce) != self.NONCE_LEN:
            raise ValueError(f"Invalid ASCON-128a nonce length: expected {self.NONCE_LEN}, got {len(nonce)}")

        max_ciphertext_len = len(plaintext) + self.TAG_LEN
        ciphertext_buffer = (c_ubyte * max_ciphertext_len)()
        ciphertext_len = c_ulonglong(0)

        rc = self._encrypt(
            ciphertext_buffer,
            byref(ciphertext_len),
            plaintext,
            c_ulonglong(len(plaintext)),
            associated_data,
            c_ulonglong(len(associated_data)),
            None,
            nonce,
            key,
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

        rc = self._decrypt(
            plaintext_buffer,
            byref(plaintext_len),
            None,
            ciphertext,
            c_ulonglong(len(ciphertext)),
            associated_data,
            c_ulonglong(len(associated_data)),
            nonce,
            key,
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
        self.master_shared_key = master_shared_key[:16]
        self.replay_tracker = GooseReplayTracker()
        self.boot_id = os.urandom(4)
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
            return "ASCON-128a (Python ascon) + GOOSE Nonce (Byte Stream)"
        return "ASCON-128a (ascon-c) + GOOSE Nonce (Byte Stream)"

    def protect(self, raw_message: bytes) -> tuple[bytes, dict]:
        t_start_total = time.perf_counter()
        
        st_num, sq_num = extract_goose_state_numbers(raw_message)
        nonce12 = self.boot_id + st_num.to_bytes(4, "big") + sq_num.to_bytes(4, "big")
        nonce16 = nonce12 + b"\x00\x00\x00\x00"
        
        # 3. ASCON Encryption
        t2 = time.perf_counter()
        ciphertext = self._ascon.encrypt(self.master_shared_key, nonce16, nonce12, raw_message)
        t_encrypt = (time.perf_counter() - t2) * 1000
        t_total_encrypt = (time.perf_counter() - t_start_total) * 1000

        # ---------------------------------------------------------
        # PURE BYTE STREAM: [NONCE (12)] + [CIPHERTEXT + TAG]
        # ---------------------------------------------------------
        secure_stream = nonce12 + ciphertext

        metrics = {
            "pub_encrypt_ms": t_encrypt,
            "pub_total_crypto_ms": t_total_encrypt
        }
        return secure_stream, metrics

    def verify(self, secure_stream: bytes) -> tuple[bytes, dict]:
        # ---------------------------------------------------------
        # SLICING: [NONCE (12)] + [CIPHERTEXT + TAG]
        # ---------------------------------------------------------
        nonce12 = secure_stream[:12]
        ciphertext = secure_stream[12:]
        boot_id = nonce12[:4]
        st_num = int.from_bytes(nonce12[4:8], "big")
        sq_num = int.from_bytes(nonce12[8:12], "big")
        nonce16 = nonce12 + b"\x00\x00\x00\x00"
        
        metrics = {}
        t_start_total = time.perf_counter()

        # 1. Replay Attack / sqNum Check (boot_id, stNum aware)
        t0 = time.perf_counter()
        if not self.replay_tracker.is_acceptable(boot_id, st_num, sq_num):
            raise ValueError(
                f"Replay Attack! boot_id={boot_id.hex()} stNum={st_num} sqNum={sq_num}"
            )
        metrics["sub_replay_check_ms"] = (time.perf_counter() - t0) * 1000

        # 2. ASCON Decryption & Authentication
        t2 = time.perf_counter()
        try:
            raw_message = self._ascon.decrypt(self.master_shared_key, nonce16, nonce12, ciphertext)
        except Exception:
            raise ValueError("Data Tampering Detected! ASCON authentication failed.")

        self.replay_tracker.commit(boot_id, st_num, sq_num)
            
        metrics["sub_decrypt_ms"] = (time.perf_counter() - t2) * 1000
        metrics["sub_total_crypto_ms"] = (time.perf_counter() - t_start_total) * 1000

        return raw_message, metrics