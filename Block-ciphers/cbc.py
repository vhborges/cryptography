from os import urandom
from typing import Union, Iterator

import common

# creating a constant IV to demonstrate the avalanche effect
iv = common.generate_iv()

def cbc_encryption(blocks: Iterator, keys: list):
    ciphertext = iv
    next_iv = iv
    for block in blocks:
        cipherblock = common.encrypt_block(block, keys, next_iv)
        next_iv = cipherblock
        ciphertext += cipherblock
    return ciphertext

def cbc_decryption(blocks: Iterator, keys: list):
    next_iv = next(blocks)
    plaintext = bytes()
    for block in blocks:
        plainblock = common.decrypt_block(block, keys, next_iv)
        next_iv = block
        plaintext += plainblock
    return plaintext

def encrypt(plaintext: str, key: bytes) -> bytes:
    return common.encrypt(plaintext, key, cbc_encryption)

def decrypt(ciphertext: bytes, key: bytes) -> Union[str, bytes]:
    return common.decrypt(ciphertext, key, cbc_decryption)
