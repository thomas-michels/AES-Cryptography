
def pkcs7(text: bytes, block_size: int) -> bytes:
    qtd_bytes = len(text) % block_size
    padding = (block_size - qtd_bytes) * chr(block_size - qtd_bytes)
    return text + bytes(padding, "utf-8")


def unpad_pkcs7(text: bytes, block_size: int) -> str:
    qtd_bytes = bytearray(text)[-1]
    padding = qtd_bytes * chr(qtd_bytes)
    return text[:len(padding)* -1]
