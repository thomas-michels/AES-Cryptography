from typing import List


class SecretKey:

    __key: bytes
    __size: int

    def __init__(self, key: bytes) -> None:
        self.__key = key
        self.__calculate_key_size()

    def __calculate_key_size(self) -> None:
        self.__size = len(self.__key) * 8

    def get_key(self) -> List:
        return self.__key.hex(",").split(",")

    def get_size_in_bits(self) -> int:
        return self.__size
