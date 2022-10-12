from src.adapters import SecretKeyAdapter
from src.cryptography import AESAlgorithm
from src.utils import CipherMode


class Application:
    def run(self):
        secret_key = SecretKeyAdapter.from_string("ABCDEFGHIJKLMOPQ")

        aes = AESAlgorithm(CipherMode.ECB_MODE, secret_key)

        print(aes.encrypt(b"ABC"))
