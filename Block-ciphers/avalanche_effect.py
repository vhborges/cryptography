import ecb, cbc, pcbc, common

KEY = b'arroz'

def ecb_avalanche_effect():
    print('---------- ECB ----------')

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the ECB mode of encryption is predictable'
    print('Original plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = ecb.encrypt(plaintext, KEY)
    print('Ciphertext:', ciphertext, end="\n\n")
    print('List of bytes of the ciphertext:', list(ciphertext), sep='\n', end="\n\n")

    plaintext = ecb.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the ECB mode of encription is predictable'
    print('Modified plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = ecb.encrypt(plaintext, KEY)
    print('Ciphertext:', ciphertext, end="\n\n")
    print('List of bytes of the ciphertext:', list(ciphertext), sep='\n', end="\n\n")

    plaintext = ecb.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")

def cbc_avalanche_effect():
    print('---------- CBC ----------')

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the CBC mode of encryption is vulnerable to bit flipping'
    print('Original plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = cbc.encrypt(plaintext, KEY)
    print('Ciphertext:', ciphertext, end="\n\n")
    print('List of bytes of the ciphertext:', list(ciphertext), sep='\n', end="\n\n")

    plaintext = cbc.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the CBC mode of encription is vulnerable to bit flipping'
    print('Modified plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = cbc.encrypt(plaintext, KEY)
    print('Ciphertext:', ciphertext, end="\n\n")
    print('List of bytes of the ciphertext:', list(ciphertext), sep='\n', end="\n\n")

    plaintext = cbc.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")

def pcbc_avalanche_effect():
    print('---------- PCBC ----------')

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the PCBC mode of encryption is NOT vulnerable to bit flipping'
    print('Original plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = pcbc.encrypt(plaintext, KEY)
    print('Ciphertext:', ciphertext, end="\n\n")
    print('List of bytes of the ciphertext:', list(ciphertext), sep='\n', end="\n\n")

    plaintext = pcbc.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")

    plaintext = 'From:Lucas\nTo:Pedro\nContent:the PCBC mode of encription is NOT vulnerable to bit flipping'
    print('Modified plaintext:', plaintext, sep='\n', end='\n\n')
    ciphertext = pcbc.encrypt(plaintext, KEY)
    print('Ciphertext:', ciphertext, end="\n\n")
    print('List of bytes of the ciphertext:', list(ciphertext), sep='\n', end="\n\n")

    plaintext = pcbc.decrypt(ciphertext, KEY)
    print('Decrypted ciphertext:', plaintext, sep='\n', end="\n\n")

ecb_avalanche_effect()
cbc_avalanche_effect()
pcbc_avalanche_effect()
