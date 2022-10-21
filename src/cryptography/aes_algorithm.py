# Feito por Thomas Michels Rodrigues e Gabriel Dallarosa

from typing import List
from .base_crypto_algorithm import CryptoAlgorithm
from .secret_key import SecretKey
from src.utils import CipherMode, GaloisField, SBox


class AESAlgorithm(CryptoAlgorithm):

    __key: SecretKey
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
        self.__state = self.__set_state_matrix(self.__key.get_key())
        self.__set_key_schedule()

    def __validate_key(self):
        key_size = self.__key.get_size_in_bits()
        if key_size != 128 and key_size != 192 and key_size != 256:
            raise ValueError("Key must have 128, 192 or 256 bits")

    def encrypt(self, text: bytes) -> bytes:
        blocks = self.__get_blocks(text)
        count = 1
        blocks_encrypted = []

        for block in blocks:
            start = 0
            end = 4
            # etapa 1 criptografia
            round_keys = self.__key_schedule[start:end]

            A = []
            for j in range(4):
                A.append(self.__complete_xor(block[j], round_keys[j]))

            for i in range(1, 10):
                # etapa 2 criptografia
                B = []
                for word in A:
                    B.append(self.__sub_bytes(word))

                # etapa 3 criptografia até aqui ta certo 100%
                C = self.__shift_rows(B)

                # etapa 4 criptografia
                D = self.__mix_columns(C)
                
                # etapa 5 criptografia

                A = []
                start += 4
                end += 4
                round_keys = self.__key_schedule[start:end]

                for k in range(4):
                    A.append(self.__complete_xor(D[k], round_keys[k]))
            
            # etapa 2 criptografia até aqui ta certo
            B = []
            for word in A:
                B.append(self.__sub_bytes(word))

            # etapa 3 criptografia
            C = self.__shift_rows(B)

            # etapa 5 criptografia
            A = []
            round_keys = self.__key_schedule[40:44]
            for l in range(4):
                A.append(self.__complete_xor(C[l], round_keys[l]))

            print(f"BLOCK - {count}: {A}")
            count += 1
            blocks_encrypted.append(A)

        result = self.__export_blocks(blocks_encrypted)
        return result

    def __export_blocks(self, blocks: List[List[str]]) -> str:
        result = ""
        for block in blocks:
            for i in range(4):
                for j in range(4):
                    result += f"{block[i][j]}"
                    if not (i == 3 and j == 3):
                        result += " "
            result += " "
            
        return result

    def __mix_columns(self, shifted_rows: List) -> List[List[str]]:
        mixed_columns = [[], [], [], []]
        for i in range(4):
            mixed_columns[i].append(self.__xor_mix_columns(shifted_rows[i], "2", "3", "1", "1"))
            mixed_columns[i].append(self.__xor_mix_columns(shifted_rows[i], "1", "2", "3", "1"))
            mixed_columns[i].append(self.__xor_mix_columns(shifted_rows[i], "1", "1", "2", "3"))
            mixed_columns[i].append(self.__xor_mix_columns(shifted_rows[i], "3", "1", "1", "2"))

        return mixed_columns

    def __xor_mix_columns(self, shited_row: List[str], m1, m2, m3, m4) -> str:
        first_term = self.__galois_field.multiply(shited_row[0], m1)
        second_term = self.__galois_field.multiply(shited_row[1], m2)
        third_term = self.__galois_field.multiply(shited_row[2], m3)
        fourth_term = self.__galois_field.multiply(shited_row[3], m4)

        first_xor = hex(int(first_term, 16) ^ int(second_term, 16)).replace("0x", "").zfill(2)
        second_xor = hex(int(third_term, 16) ^ int(fourth_term, 16)).replace("0x", "").zfill(2)
        third_xor = hex(int(first_xor, 16) ^ int(second_xor, 16)).replace("0x", "").zfill(2)
        return third_xor

    def __shift_rows(self, sub_words: List[str]) -> List[str]:
        shifted_rows = [[], [], [], []]

        for i in range(4):
            line = [
                sub_words[0][i],
                sub_words[1][i],
                sub_words[2][i],
                sub_words[3][i],
            ]

            for j in range(i):
                line = self.__rot_word(line)
            
            shifted_rows[0].append(line[0])
            shifted_rows[1].append(line[1])
            shifted_rows[2].append(line[2])
            shifted_rows[3].append(line[3])

        return shifted_rows

    def __sub_bytes(self, word: List[str]) -> List:
        result = list(map(lambda x: self.__sbox.get_hex(x[0], x[1]), word))
        return result

    def __get_blocks(self, text: bytes) -> List:
        text_hex = text.hex(",")
        text_list = text_hex.split(",")
        blocks = []
        if len(text_list) % 16 != 0:
            raise Exception("Entrada invalida, a entrada precisa formar blocos de 16 bytes")
        
        qtd_blocks = int(len(text_list) / 16)
        start_pos = 0

        for i in range(1, qtd_blocks + 1):
            final_pos = i*16
            text_to_block = text_list[start_pos:final_pos]
            
            blocks.append(self.__set_state_matrix(text_to_block))
            start_pos = final_pos

        return blocks

    def __set_state_matrix(self, block: List[str]) -> List:
        state = [[], [], [], []]

        for i in range(4):
            char_pos = i

            for j in range(4):
                state[j].append(block[char_pos])
                char_pos += 4

        return state

    def __set_key_schedule(self):
        print("Construindo a Key Schedule")
        self.__key_schedule.extend(self.__state)
        
        for i in range(1, 11):
            # etapa 1
            last_round_key = self.__key_schedule[-1].copy()

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

        print("Key Schedule gerada")

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

    def __complete_xor(self, first_word: List, xor_round_constant: List) -> List[str]:
        result = list(map(lambda x: hex(int(first_word[x], 16) ^ int(xor_round_constant[x], 16)).replace("0x", "").zfill(2), [0, 1, 2, 3]))
        return result
