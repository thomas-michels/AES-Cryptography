from .base_crypto_algorithm import CryptoAlgorithm


class AESAlgorithm(CryptoAlgorithm):

    def __init__(self, key) -> None:
        self.key = key

        self.validate_key()

    def validate_key(self):
        if type(self.key) is not bytes:
            self.key = bytes(self.key)
        
        key_size = len(self.key)
        if key_size != 128 or key_size != 192 or key_size != 256:
            raise ValueError("Key must have length 128, 192 or 256 bytes")

    def encrypt(self, text: bytes) -> bytes:
        pass
