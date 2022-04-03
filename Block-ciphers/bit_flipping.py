import ecb, cbc, pcbc, common

KEY = b'arroz'

def ecb_bitflipping():
    print('---------- ECB ----------')

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the ECB mode of encryption is predictable'
    print('Original plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = ecb.encrypt(plaintext, KEY)

    ##### here I try to modify the second block - change Pedro to Mario #####
    block = bytearray(ciphertext[ecb.BLOCK_SIZE:ecb.BLOCK_SIZE*2])
    block[4:9] = common.xor(block[4:9], common.xor(b'Pedro', b'Mario'))
    ciphertext = ciphertext[:ecb.BLOCK_SIZE] + block + ciphertext[ecb.BLOCK_SIZE*2:]
    #################################################

    print('Bitflipping Pedro to Mario...')
    plaintext = ecb.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")


def cbc_bitflipping():
    print('---------- CBC ----------')

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the CBC mode of encryption is vulnerable to bit flipping'
    print('Original plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = cbc.encrypt(plaintext, KEY)

    iv = bytearray(ciphertext[:cbc.IV_SIZE])
    iv[5:] = common.xor(iv[5:], common.xor(b'Lucas', b'Mario'))
    ciphertext = bytes(iv) + ciphertext[cbc.IV_SIZE:]

    print('Bitflipping Lucas to Mario...')
    plaintext = cbc.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")

    ##### modifying the second block #####
    block = bytearray(ciphertext[cbc.BLOCK_SIZE:cbc.BLOCK_SIZE*2])
    block[4:9] = common.xor(block[4:9], common.xor(b'Pedro', b'Mario'))
    ciphertext = ciphertext[:cbc.BLOCK_SIZE] + block + ciphertext[cbc.BLOCK_SIZE*2:]
    ######################################

    print('Bitflipping Pedro to Mario...')
    plaintext = cbc.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, end="\n\n")

def pcbc_bitflipping():
    print('---------- PCBC ----------')

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the PCBC mode of encryption is NOT vulnerable to bit flipping'
    print('Original plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = cbc.encrypt(plaintext, KEY)

    iv = bytearray(ciphertext[:pcbc.IV_SIZE])
    iv[5:] = common.xor(iv[5:], common.xor(b'Lucas', b'Mario'))
    ciphertext = bytes(iv) + ciphertext[pcbc.IV_SIZE:]

    print('Bitflipping Lucas to Mario...')
    plaintext = pcbc.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")
    print('List of bytes of the plaintext:', list(bytes(plaintext, 'utf-8')), sep='\n', end="\n\n")

    ##### modifying the second block #####
    block = bytearray(ciphertext[pcbc.BLOCK_SIZE:pcbc.BLOCK_SIZE*2])
    block[4:9] = common.xor(block[4:9], common.xor(b'Pedro', b'Mario'))
    ciphertext = ciphertext[:pcbc.BLOCK_SIZE] + block + ciphertext[pcbc.BLOCK_SIZE*2:]
    ######################################

    print('Bitflipping Pedro to Mario...')
    plaintext = pcbc.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, end="\n\n")

ecb_bitflipping()
cbc_bitflipping()
pcbc_bitflipping()
