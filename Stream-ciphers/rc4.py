"""Simula o funcionamento do algoritmo criptográfico rc4"""

import os

def ksa(key:bytes) -> list:
    S = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prg(plaintext:bytes, key:bytes) -> bytes:
    S = ksa(key)
    i = 0
    j = 0
    keystream = []
    tam = len(plaintext)
    for _ in range(tam):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)

def random(size:int) -> bytes:
    return os.urandom(size)

def probValor(plaintext:str, pos:int, val:int, nroIter:int, tamChave:int) -> float:
    """Calcula a probabilidade de que o valor 'val' apareça na posição 'pos' das keystreams
    geradas pelo prg com o 'plaintext', usando 'nroIter' iterações e chaves de tamanho 'tamChave'"""
    freq = val
    for _ in range(nroIter):
        keystream = prg(plaintext, random(tamChave))
        if keystream[pos] == val:
            freq += 1
    return freq/nroIter

def encripta(plaintext:str, chave:bytes) -> bytes:
    plaintext = bytes(plaintext, 'utf-8')
    keystream = prg(plaintext, chave)
    ciphertext = bytes()
    for p, k in zip(plaintext, keystream):
        ciphertext += bytes([p^k])
    return ciphertext

def decripta(ciphertext:bytes, chave:bytes) -> str:
    keystream = prg(ciphertext, chave)
    plaintext = bytes()
    for c, k in zip(ciphertext, keystream):
        plaintext += bytes([c^k])
    return plaintext.decode('utf-8')

def main():
    #tam = 40
    #chave = bytes(input("Chave: "), encoding='ascii')
    #keystream = prg(tam, chave)
    #print(list(keystream))
    chave = b'chave'
    plaintext = 'Jamais, em hipotese alguma, deixe um Vogon ler poesias para voce.'
    ciphertext = encripta(plaintext, chave)
    print("Ciphertext:", ciphertext.hex())
    #plaintext = decripta(ciphertext, chave)
    #print("Plaintext:", plaintext)

if __name__ == "__main__":
    main()
