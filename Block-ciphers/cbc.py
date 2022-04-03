from os import urandom
from typing import Union, Iterator

import common

IV_SIZE = 10
BLOCK_SIZE = 10
ROUND_QTY = 10

# creating a constant IV to demonstrate the avalanche effect
iv = urandom(IV_SIZE)

def cbc_encryption(blocks: Iterator, keys: list):
    global iv
    ciphertext = iv
    for block in blocks:
        cipherblock = common.encrypt_block(block, keys, iv)
        iv = cipherblock
        ciphertext += cipherblock
    return ciphertext

def cbc_decryption(blocks: Iterator, keys: list):
    iv = next(blocks)
    plaintext = bytes()
    for block in blocks:
        plainblock = common.decrypt_block(block, keys, iv)
        iv = block
        plaintext += plainblock
    return plaintext

def encrypt(plaintext: str, key: bytes) -> bytes:
    return common.encrypt(plaintext, key, BLOCK_SIZE, ROUND_QTY, cbc_encryption)

def decrypt(ciphertext: bytes, key: bytes) -> Union[str, bytes]:
    return common.decrypt(ciphertext, key, BLOCK_SIZE, ROUND_QTY, cbc_decryption)
