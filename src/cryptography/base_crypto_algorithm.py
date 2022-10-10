from abc import ABC, abstractclassmethod


class CryptoAlgorithm(ABC):

    @abstractclassmethod
    def encrypt(self, text: bytes) -> bytes:
        raise Exception("encrypt not implemented")
