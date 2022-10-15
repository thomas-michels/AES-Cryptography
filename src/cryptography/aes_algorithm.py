from typing import List
from .base_crypto_algorithm import CryptoAlgorithm
from .secret_key import SecretKey
from src.utils import CipherMode, GaloisField, SBox


class AESAlgorithm(CryptoAlgorithm):

    __key: SecretKey
    __mode: CipherMode
    __key_schedule = []
    __state = [[], [], [], []]
    __galois_field: GaloisField
    __sbox: SBox
    __rcon: List[str] = ["01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"]

    def __init__(self, mode: CipherMode, key: SecretKey) -> None:
        self.__key = key
        self.__mode = mode

        self.__galois_field = GaloisField()
        self.__sbox = SBox()

        self.__validate_key()
        self.__set_state_matrix()
        self.__set_key_schedule()

    def __validate_key(self):
        key_size = self.__key.get_size_in_bits()
        if key_size != 128 and key_size != 192 and key_size != 256:
            raise ValueError("Key must have 128, 192 or 256 bits")

    def encrypt(self, text: bytes) -> bytes:
        return self.__set_state_matrix()

    def __set_state_matrix(self):
        char_pos = 0
        key = self.__key.get_key()
        keys = key.split(",")
        for i in range(4):
            for j in range(4):
                self.__state[j].append(keys[char_pos])
                char_pos += 1

    def __set_key_schedule(self):
        self.__key_schedule.extend(self.__state)
        
        for i in range(1, 11):
            # etapa 1
            last_round_key = self.__key_schedule[-1]

            # etapa 2
            rotated_word = self.__rot_word(last_round_key)

            # etapa 3
            sub_word = self.__sub_word(rotated_word)
            
            # etapa 4
            round_constant = self.__round_constant(i)

            # etapa 5
            xor_round_constant = self.__xor_rcon(sub_word, round_constant)

            # etapa 6
            result = self.__complete_xor(self.__key_schedule[4 * (i - 1)], xor_round_constant)
            
            self.__key_schedule.append(result)

            for j in range(3):
                ks_size = len(self.__key_schedule)
                result = self.__complete_xor(self.__key_schedule[ks_size - 4], self.__key_schedule[-1])
                self.__key_schedule.append(result)

        print(len(self.__key_schedule))

    def __rot_word(self, last_round_key: list) -> List:
        first_byte = last_round_key[0]
        last_round_key.pop(0)
        last_round_key.append(first_byte)
        return last_round_key

    def __sub_word(self, rotated_word: List) -> List:
        sub_word = list(map(lambda x: self.__sbox.get_hex(x[0], x[1]), rotated_word))
        return sub_word

    def __round_constant(self, round_key) -> List:
        first_byte = self.__rcon[round_key - 1]
        return [first_byte, 0, 0, 0]

    def __xor_rcon(self, sub_word: List, round_constant: List) -> List:
        xor_rcon = hex(int(sub_word[0], 16) ^ int(round_constant[0], 16))
        xor_rcon = xor_rcon.replace("0x", "")
        return [xor_rcon, sub_word[1], sub_word[2], sub_word[3]]

    def __complete_xor(self, first_word: List, xor_round_constant: List) -> List:
        result = list(map(lambda x: hex(int(first_word[x], 16) ^ int(xor_round_constant[x], 16)).replace("0x", "").zfill(2), [0, 1, 2, 3]))
        return result
