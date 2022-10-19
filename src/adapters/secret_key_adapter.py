from src.cryptography import SecretKey


class SecretKeyAdapter:

    @classmethod
    def from_string(self, key: str) -> SecretKey:
        if key[0].isdigit():
            key = [hex(int(i)).replace("0x", "").zfill(2) for i in key.split(',')]
        else:
            key = bytes(key.replace(",", ""), "utf-8")

        return SecretKey(key)

    @classmethod
    def from_bytes(self, key: bytes) -> SecretKey:
        return SecretKey(key)

    @classmethod
    def from_hex(self, key: str) -> SecretKey:
        key = bytes.fromhex(key)
        return SecretKey(key)
