from abc import ABC, abstractclassmethod
from src.utils import CipherMode
from .secret_key import SecretKey


class CryptoAlgorithm(ABC):

    @abstractclassmethod
    def encrypt(self, text: bytes) -> bytes:
        raise Exception("encrypt not implemented")
