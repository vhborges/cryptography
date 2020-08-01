from utils import readFile, writeFile, xorBytes, randomBytes

def encrypt(key, plaintext):
    ciphertext = xorBytes(key, plaintext)
    return ciphertext

def main():
    messages = readFile('plaintexts.txt')
    assert messages, "Empty 'plaintext.txt' file!"
    messagesBytes = [msg.encode() for msg in messages]
    key = randomBytes(max(len(msg) for msg in messagesBytes))
    ciphertexts = [encrypt(key, msg).hex() for msg in messagesBytes]
    writeFile('ciphertexts.txt', ciphertexts)
    writeFile('keys.txt', [key.hex()])

if __name__ == '__main__':
    main()
