from utils import readFile, writeFile, xorBytes, randomBytes

def encrypt(key, plaintext):
    ciphertext = xorBytes(key, plaintext)
    return ciphertext

def main():
    messages = readFile('plaintexts.txt')
    assert messages, "Empty 'plaintext.txt' file!"
    messagesBytes = [msg.encode() for msg in messages]
    keys = [randomBytes(len(msg)) for msg in messagesBytes]
    ciphertexts = [encrypt(key, msg).hex() for key, msg in zip(keys, messagesBytes)]
    writeFile('ciphertexts.txt', ciphertexts)
    writeFile('keys.txt', [key.hex() for key in keys])

if __name__ == '__main__':
    main()
