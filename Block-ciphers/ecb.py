import common
from typing import Union, Iterator

BLOCK_SIZE = 10
ROUND_QTY = 10

def ecb_encryption(blocks: Iterator, keys: list):
    ciphertext = bytes()
    for block in blocks:
        cipherblock = common.encrypt_block(block, keys)
        ciphertext += cipherblock
    return ciphertext

def ecb_decryption(blocks: Iterator, keys: list):
    plaintext = bytes()
    for block in blocks:
        plainblock = common.decrypt_block(block, keys)
        plaintext += plainblock
    return plaintext

def encrypt(plaintext: str, key: bytes) -> bytes:
    return common.encrypt(plaintext, key, BLOCK_SIZE, ROUND_QTY, ecb_encryption)

def decrypt(ciphertext: bytes, key: bytes) -> Union[str, bytes]:
    return common.decrypt(ciphertext, key, BLOCK_SIZE, ROUND_QTY, ecb_decryption, ecb=True)
