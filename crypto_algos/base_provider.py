# File: crypto_algos/base_provider.py

class CryptoProvider:
    """
    Abstract base class for all cryptographic algorithms.
    Ensures a unified Strategy Design Pattern for the Publisher and Subscriber.
    """
    def get_algo_name(self) -> str:
        raise NotImplementedError
        
    def protect(self, raw_message: bytes) -> dict:
        """
        Encrypts/Signs the message. Returns a dictionary payload.
        Must include 'metrics' dictionary for latency tracking.
        """
        raise NotImplementedError
        
    def verify(self, payload: dict) -> tuple[bytes, dict]:
        """
        Verifies/Decrypts the message. 
        Returns (decrypted_raw_message_bytes, timing_metrics_dict).
        Throws ValueError on Replay Attack or MAC tampering.
        """
        raise NotImplementedError