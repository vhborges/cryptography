from os import urandom
from typing import Union, Iterator

import common

IV_SIZE = 10
BLOCK_SIZE = 10
ROUND_QTY = 10

# creating a constant IV to demonstrate the avalanche effect
iv = common.generate_iv()

def pcbc_encryption(blocks: Iterator, keys: list) -> bytes:
    ciphertext = iv
    next_iv = iv
    for block in blocks:
        cipherblock = common.encrypt_block(block, keys, next_iv)
        next_iv = common.xor(block, cipherblock)
        ciphertext += cipherblock
    return ciphertext

def pcbc_decryption(blocks: Iterator, keys: list) -> Union[str, bytes]:
    next_iv = next(blocks)
    plaintext = bytes()
    for block in blocks:
        plainblock = common.decrypt_block(block, keys, next_iv)
        next_iv = common.xor(block, plainblock)
        plaintext += plainblock
    return plaintext

def encrypt(plaintext: str, key: bytes) -> bytes:
    return common.encrypt(plaintext, key, pcbc_encryption)

def decrypt(ciphertext: bytes, key: bytes) -> Union[str, bytes]:
    return common.decrypt(ciphertext, key, pcbc_decryption)
