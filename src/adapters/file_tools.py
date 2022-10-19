
def read_file(path: str) -> bytes:
    print(f"Lendo arquivo com o path {path}")

    with open(path, 'rb') as file:
        lines = file.read()
        return lines


def save_file(name: str, type: str, content, mode="wb"):
    print(f"Salvando o arquivo {name + type}")
    with open(name + type, mode) as file:
        file.write(content)

    print("Arquivo salvo")
