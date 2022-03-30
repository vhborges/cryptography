from Crypto.Hash import SHA256

def divide(mensagem: bytes, tam_bloco: int):
    """ Retorna um Generator para blocos da 'mensagem' de tamanho 'tam_bloco', em ordem inversa """

    qtd_blocos_int = len(mensagem) // tam_bloco

    ultimo_bloco = mensagem[qtd_blocos_int*tam_bloco:(qtd_blocos_int+1)*tam_bloco]
    yield ultimo_bloco

    for num_bloco in range(qtd_blocos_int - 1, -1, -1):
        bloco = mensagem[num_bloco*tam_bloco:(num_bloco+1)*tam_bloco]
        yield bloco

def calcula_hash(bloco: bytes) -> bytes:
    return SHA256.new(bloco).digest()

def concatena_hash(bloco: bytes, hash_: bytes) -> bytes:
    return bloco + hash_

def main():
    video = 'video.mp4'
    with open(video, 'rb') as file:
        conteudo = file.read()

    blocos = divide(conteudo, 1024)

    bloco = next(blocos)
    while True:
        hash_ = calcula_hash(bloco)
        try:
            bloco = next(blocos)
        except StopIteration:
            break
        bloco = concatena_hash(bloco, hash_)

    print(hash_.hex())

if __name__ == '__main__':
    main()
