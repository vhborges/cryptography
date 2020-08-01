"""
This attack explores the vulnerability where one uses the One-time pad (or some Stream-ciphers) to encrypt multiple messages using the same key.

For this attack to work, the file with must contain enough ciphertexts to give a good hint of where the spaces of each message are located.
Ciphertexts with similar lengths is also helpful, as the longer ones will have less characters to xor with near their ends.
"""

from utils import readFile, printList, xorBytes

# find possible space characters contained either on cipher1 or cipher2 using the resulting xor of both
def findSpaces(cipher1, cipher2, frequencies):
    cipher1 = bytes.fromhex(cipher1)
    cipher2 = bytes.fromhex(cipher2)
    c1Xc2 = xorBytes(cipher1, cipher2)
    for i, asciiNum in enumerate(c1Xc2):
        if hasSpace(asciiNum):
            frequencies[i] += 1

def hasSpace(xorResult):
    if 65 <= xorResult <= 90 or\
            97 <= xorResult <= 122 or\
            xorResult == 0:
        return True
    else:
        return False

def computeKey(ciphertexts):
    keySize = max(len(cipher)//2 for cipher in ciphertexts)
    key = [None]*keySize
    maxFrequency = [0]*keySize
    for cipher1 in ciphertexts:
        frequencies = [0]*(len(cipher1)//2)
        for cipher2 in ciphertexts:
            if cipher1 != cipher2:
                findSpaces(cipher1, cipher2, frequencies)
        cipher1 = bytes.fromhex(cipher1)
        for pos, freq in zip(range(len(frequencies)), frequencies):
            limit = numberOfMsgs(ciphertexts, pos) - 1
            margin = limit//4
            if (freq >= limit - margin) and (freq > maxFrequency[pos]):
                maxFrequency[pos] = freq
                key[pos] = cipher1[pos] ^ ord(' ')
    return key

# number of messages whose size is bigger than pos (2*pos on hexadecimal)
def numberOfMsgs(ciphertexts, pos):
    pos *= 2
    return sum(1 for msg in ciphertexts if len(msg) > pos)

def computePlaintext(ciphertext, key):
    ciphertext = bytes.fromhex(ciphertext)
    plaintext = ""
    for a,b in zip(ciphertext, key):
        if b != None:
            plaintext += chr(a ^ b)
        else:
            plaintext += "_"
    return plaintext

def plaintextsList(ciphertexts, key):
    plaintexts = []
    for msg in ciphertexts:
        plaintexts.append(computePlaintext(msg, key))
    return plaintexts

# update the key when knowing that plaintext[pos] == string
def modifyKey(ciphertexts, key, string, pos, msgNo):
    size = len(string)
    for i in range(pos, pos+size):
        key[i] = ord(string[i-pos]) ^ int(ciphertexts[msgNo][i*2:i*2+2], 16)

def main():
    ciphertexts = readFile('ciphertexts.txt')

    key = computeKey(ciphertexts)

    plaintexts = plaintextsList(ciphertexts, key)

    printList(plaintexts)

if __name__ == '__main__':
    main()

