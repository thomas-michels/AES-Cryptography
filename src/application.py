from src.adapters import SecretKeyAdapter, save_file, read_file
from src.cryptography import AESAlgorithm
from src.utils import CipherMode, unpad_pkcs7, pkcs7

from Crypto.Cipher import AES


class Application:
    def run(self):
        secret_key = SecretKeyAdapter.from_string("20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248")

        lib_aes_descryptograph = AES.new(secret_key.get_key_in_bytes(), AES.MODE_ECB)

        # Encrypt
        aes = AESAlgorithm(CipherMode.ECB_MODE, secret_key)
        text = read_file("teste.txt")

        pad = pkcs7(text, 16)

        encrypted = aes.encrypt(pad)

        save_file("teste-encrypt", ".txt", encrypted, "w")

        # Decrypt - prova real
        decrypting = lib_aes_descryptograph.decrypt(bytes.fromhex(encrypted))

        unpad = unpad_pkcs7(decrypting)

        save_file("teste-decrypt", ".txt", unpad, "wb")
