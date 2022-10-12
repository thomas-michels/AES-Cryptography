from .base_crypto_algorithm import CryptoAlgorithm
from .secret_key import SecretKey
from src.utils import CipherMode


class AESAlgorithm(CryptoAlgorithm):

    __key: SecretKey
    __mode: CipherMode
    __key_schedule = []

    def __init__(self, mode: CipherMode, key: SecretKey) -> None:
        self.__key = key
        self.__mode = mode

        self.__validate_key()

    def __validate_key(self):
        key_size = self.__key.get_size_in_bits()
        if key_size != 128 and key_size != 192 and key_size != 256:
            raise ValueError("Key must have 128, 192 or 256 bits")

    def encrypt(self, text: bytes) -> bytes:
        return self.__set_state_matrix()

    def __set_state_matrix(self):
        state_matrix = [[], [], [], []]
        char_pos = 0
        key = self.__key.get_key()
        for i in range(4):
            for j in range(4):
                state_matrix[j].append(key[char_pos])
                char_pos += 1

        return state_matrix

    def __key_expansion(self):
        pass
