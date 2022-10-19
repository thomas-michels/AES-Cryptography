from typing import List


class SecretKey:

    __size: int

    def __init__(self, key) -> None:
        if type(key) is list:
            self.key = key

        elif type(key) is bytes:
            self.key = key.hex(",").split(",")

        self.__calculate_key_size()

    def __calculate_key_size(self) -> None:
        self.__size = len(self.key) * 8

    def get_key(self) -> List:
        return self.key

    def get_key_in_bytes(self) -> bytes:
        b = b""
        for i in self.key:
            b += bytes.fromhex(i)

        return b

    def get_size_in_bits(self) -> int:
        return self.__size
