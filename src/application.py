from src.adapters import SecretKeyAdapter
from src.cryptography import AESAlgorithm
from src.utils import CipherMode

from Crypto.Cipher import AES


class Application:
    def run(self):
        outro_aes = AES.new(b"ABCDEFGHIJKLMNOP", AES.MODE_ECB)
        secret_key = SecretKeyAdapter.from_bytes(b"ABCDEFGHIJKLMNOP")

        aes = AESAlgorithm(CipherMode.ECB_MODE, secret_key)

        encrypted = aes.encrypt(b"DESENVOLVIMENTO!")
        print(encrypted)
        b = bytes.fromhex(encrypted)
        de = outro_aes.decrypt(b)
        print(str(de, "utf-8"))
