from src.adapters import SecretKeyAdapter, save_file, read_file
from src.cryptography import AESAlgorithm
from src.utils import CipherMode, unpad_pkcs7, pkcs7

from Crypto.Cipher import AES


class Application:
    def run(self, key, entrance_data_file, exit_data_file):
        secret_key = SecretKeyAdapter.from_string(key)

        lib_aes_descryptograph = AES.new(secret_key.get_key_in_bytes(), AES.MODE_ECB)

        # Encrypt
        aes = AESAlgorithm(CipherMode.ECB_MODE, secret_key)
        text = read_file(entrance_data_file)

        pad = pkcs7(text, 16)

        encrypted = aes.encrypt(pad)

        save_file(exit_data_file, encrypted, "w")

        # Decrypt - prova real
        decrypting = lib_aes_descryptograph.decrypt(bytes.fromhex(encrypted))

        unpad = unpad_pkcs7(decrypting)

        save_file("decrypted-" + exit_data_file, unpad, "wb")
