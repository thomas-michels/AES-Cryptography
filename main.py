from src import Application

if __name__ == "__main__":
    app = Application()
    # key = "20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248"
    # entrance_data_file = "teste.txt"
    # exit_data_file = "teste-encrypt.txt"
    key = input("Insira a chave de 128 bits com cada byte separado por virgula: ")
    entrance_data_file = input("Arquivo de entrada de dados: ")
    exit_data_file = input("Arquivo de saida de dados: ")
    app.run(key, entrance_data_file, exit_data_file)
