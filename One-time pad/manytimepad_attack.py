"""
This attack explores the vulnerability where one uses the One-time pad (or any Stream-cipher) to encrypt multiple messages using the same key.

For this attack to work, the file with must contain enough ciphertexts to give a good hint of where the spaces of each message are located.
Ciphertexts with similar lengths is also helpful, as the longer ones will have less characters to xor with near their ends.
"""

# find possible space characters contained either on cipher1 or cipher2 using the resulting xor of both
def findSpaces(cipher1, cipher2, frequencies):
    cipher1 = bytes.fromhex(cipher1)
    cipher2 = bytes.fromhex(cipher2)
    c1Xc2 = xorb(cipher1, cipher2).hex()
    for i in range(0, len(c1Xc2), 2):
        xorResult = int(c1Xc2[i:i+2], 16)
        if hasSpace(xorResult):
            frequencies[int(i/2)] += 1

def hasSpace(xorResult):
    if 65 <= xorResult <= 90 or\
            97 <= xorResult <= 122 or\
            xorResult == 0:
        return True
    else:
        return False

def xorb(msg1, msg2):
    return bytes(a^b for a, b in zip(msg1, msg2))

def computeKey(ciphertexts):
    keySize = max(int(len(cipher)/2) for cipher in ciphertexts)
    key = [None]*keySize
    maxFrequency = [0]*keySize
    for cipher1 in ciphertexts:
        frequencies = [0]*int(len(cipher1)/2)
        for cipher2 in ciphertexts:
            if cipher1 != cipher2:
                findSpaces(cipher1, cipher2, frequencies)
        cipher1 = bytes.fromhex(cipher1)
        for pos, freq in zip(range(len(frequencies)), frequencies):
            limit = numberOfMsgs(ciphertexts, pos) - 1
            margin = int(limit/4)
            if freq >= limit-margin and freq > maxFrequency[pos]:
                maxFrequency[pos] = freq
                key[pos] = cipher1[pos]^ord(' ')
    return key

# number of messages whose size is bigger than pos (2*pos on hexadecimal)
def numberOfMsgs(ciphertexts, pos):
    pos = 2*pos
    return sum(1 for msg in ciphertexts if len(msg) > pos)

def computePlaintext(ciphertext, key):
    ciphertext = bytes.fromhex(ciphertext)
    plaintext = ""
    for a,b in zip(ciphertext, key):
        if b != None:
            plaintext += chr(a^b)
        else:
            plaintext += "_"
    return plaintext

def plaintextsList(ciphertexts, key):
    plaintexts = []
    for msg in ciphertexts:
        plaintexts.append(computePlaintext(msg, key))
    return plaintexts

def printList(l):
    for item in l:
        print(item)

# update the key when knowing that plaintext[pos] == string
def modifyKey(ciphertexts, key, string, pos, msgNo):
    size = len(string)
    for i in range(pos, pos+size):
        key[i] = ord(string[i-pos])^int(ciphertexts[msgNo][i*2:i*2+2], 16)

def readFile(file):
    with open(file) as f:
        ciphertexts = f.readlines()
    return ciphertexts

def main():
    ciphertexts = readFile('ciphertexts.txt')

    key = computeKey(ciphertexts)

    plaintexts = plaintextsList(ciphertexts, key)

    printList(plaintexts)

if __name__ == '__main__':
    main()

