from src.adapters import SecretKeyAdapter
from src.cryptography import AESAlgorithm
from src.utils import CipherMode

from Crypto.Cipher import AES


class Application:
    def run(self):
        outro_aes = AES.new(b"ABCDEFGHIJKLMNOP", AES.MODE_ECB)
        enc = outro_aes.encrypt(b"DESENVOLVIMENTO!")
        # e89639fe5021b0190e3775e77b6a2f7a
        secret_key = SecretKeyAdapter.from_bytes(b"ABCDEFGHIJKLMNOP")

        aes = AESAlgorithm(CipherMode.ECB_MODE, secret_key)

        encrypted = aes.encrypt(b"DESENVOLVIMENTO!")
        print(encrypted)
        print(f"OUTRO AES: {enc.hex()}")
        # print(encrypted)
        # b = bytes.fromhex(encrypted)
        # de = b"".join(outro_aes.decrypt(b))
        # print(str(de, "utf-8"))