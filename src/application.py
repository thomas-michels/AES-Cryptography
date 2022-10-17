from src.adapters import SecretKeyAdapter
from src.cryptography import AESAlgorithm
from src.utils import CipherMode, unpad_pkcs7, pkcs7

from Crypto.Cipher import AES


class Application:
    def run(self):
        outro_aes = AES.new(b"ABCDEFGHIJKLMNOP", AES.MODE_ECB)
        secret_key = SecretKeyAdapter.from_bytes(b"ABCDEFGHIJKLMNOP")

        aes = AESAlgorithm(CipherMode.ECB_MODE, secret_key)
        pad = pkcs7(b"DESENVOLVIMENTO!!!!!!", 16)
        print(pad)
        encrypted = aes.encrypt(pad)
        print(encrypted)
        b = bytes.fromhex(encrypted)
        de = outro_aes.decrypt(b)
        de = unpad_pkcs7(de, 16)
        print(str(de, "utf-8"))
