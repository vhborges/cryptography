from os import urandom
from random import seed, shuffle
from typing import Iterable, Callable, Union

def xor(a: bytes, b: bytes) -> bytes:
    """ Bytewise xor between a and b """
    return bytes(x^y for x, y in zip(a, b))

def prg(tam:int, key:bytes) -> bytes:
    """ RC4's PRG function """
    def ksa(key:bytes) -> list:
        S = [i for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    S = ksa(key)
    j = 0
    keystream = bytes()

    for i in range(tam):
        i = i % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream += bytes([S[(S[i] + S[j]) % 256]])

    return keystream

def iv(size: int) -> bytes:
    """ Generates an Initialization Vector """
    return urandom(size)

def generate_padding(block_size: int, last_block_size: int):
    return bytes([block_size - last_block_size] * (block_size - last_block_size))

def get_blocks(message: bytes, block_size: int, encrypt: bool = True) -> Iterable[bytes]:
    """ Divides the message 'message' in blocks of size 'block_size' and returns a Generator for them.
        Adds a padding to the last block or create a new padding block if needed. """
    if encrypt:
        last_block_size = len(message) % block_size
        message += generate_padding(block_size, last_block_size)

    block_qty = len(message) // block_size
    blocks = (message[block * block_size:(block + 1) * block_size] for block in range(block_qty))

    return blocks

def f(input_: bytes, key: bytes) -> bytes:
    ############# confusion #############
    output = list(xor(input_, key))
    #####################################

    ############# diffusion #############
    seed_ = sum(byte for byte in output)%256
    seed(seed_)
    shuffle(output)
    #####################################

    return bytes(output)

def feistel_network(block: bytes, keys: list) -> bytes:
    middle = len(block)//2
    left = block[:middle]
    right = block[middle:]

    for key in keys:
        next_right = xor(left, f(right, key))
        left = right
        right = next_right

    return (right + left)

def encrypt_block(plainblock: bytes, keys: list, iv: bytes = None) -> bytes:
    input_ = plainblock if iv == None else xor(plainblock, iv)
    cipherblock = feistel_network(input_, keys)
    return cipherblock

def decrypt_block(cipherblock: bytes, keys: list, iv: bytes = None) -> bytes:
    output = feistel_network(cipherblock, keys)
    plainblock = output if iv == None else xor(output, iv)
    return plainblock

def encrypt(plaintext: str, key: bytes, block_size: int, round_qty: int, encryption_func: Callable) -> bytes:
    if (block_size % 2) != 0:
        raise ValueError('Block size must be even')

    plaintext = bytes(plaintext, 'utf-8')

    blocks = get_blocks(plaintext, block_size)

    block_size //= 2

    # ignoring the first 4 bytes of RC4 for security
    keystream = prg(round_qty * block_size + 4, key)[4:]

    keys = [keystream[round_ * block_size:(round_ + 1) * block_size] for round_ in range(round_qty)]

    return encryption_func(blocks, keys)

def check_padding(message: bytes, last_byte: int):
    return message[-last_byte:] == [last_byte] * last_byte

def decrypt(ciphertext: bytes, key: bytes, block_size: int, round_qty: int, decryption_func: Callable, ecb: bool = False) -> Union[str, bytes]:
    if (block_size % 2) != 0:
        raise ValueError('Block size must be even')

    blocks = get_blocks(ciphertext, block_size, False)

    block_size //= 2

    # ignoring the first 4 bytes of RC4 for security
    keystream = prg(round_qty * block_size + 4, key)[4:]

    # the keys for decrypting are in reverse order
    keys = [keystream[round_ * block_size:(round_ + 1) * block_size] for round_ in range(round_qty)][-1::-1]

    plaintext = decryption_func(blocks, keys)

    end = plaintext[-1]

    if not ecb and not check_padding(plaintext, end):
        print('Warning: wrong padding!')

    try:
        return plaintext[:-end].decode('utf-8')
    except UnicodeDecodeError:
        return plaintext[:-end]
