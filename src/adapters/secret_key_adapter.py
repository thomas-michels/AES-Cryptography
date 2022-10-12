from src.cryptography import SecretKey


class SecretKeyAdapter:

    @classmethod
    def from_string(self, key: str) -> SecretKey:
        key = key.replace(",", "")
        key_bytes = key.encode("utf-8")
        return SecretKey(key_bytes)

    @classmethod
    def from_bytes(self, key: bytes) -> SecretKey:
        return SecretKey(key)

    @classmethod
    def from_hex(self, key: str) -> SecretKey:
        key = key.replace(" ", "")
        key = bytes.fromhex(key)
        return SecretKey(key)
