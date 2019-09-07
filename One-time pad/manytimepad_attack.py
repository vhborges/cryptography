"""
This attack explores the vulnerability where one uses the One-time pad (or any Stream-cipher) to encrypt multiple messages using the same key.

For this attack to work, the file with must contain enough ciphertexts to give a good hint of where the spaces of each message are located.
Ciphertexts with similar lengths is also helpful, as the longer ones will have less characters to xor with near their ends.
"""

def findSpaces(cipher1, cipher2, positions):
    cipher1 = bytes.fromhex(cipher1)
    cipher2 = bytes.fromhex(cipher2)
    c1Xc2 = xorb(cipher1, cipher2).hex()
    for i in range(0, len(c1Xc2), 2):
        xorResult = int(c1Xc2[i:i+2], 16)
        if hasSpace(xorResult):
            if int(i/2) in positions:
                positions[int(i/2)] += 1
            else:
                positions[int(i/2)] = 1

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
    keySize = max(int(len(msg)/2) for msg in ciphertexts)
    key = [None]*keySize
    maxFrequency = [0]*keySize
    for i in range(len(ciphertexts)):
        positions = {}
        for msg in ciphertexts:
            if msg != ciphertexts[i]:
                findSpaces(ciphertexts[i], msg, positions)
        msgBytes = bytes.fromhex(ciphertexts[i])
        for pos, freq in positions.items():
            filterFreq = numberOfMsgs(ciphertexts, pos)
            margin = int(filterFreq/3)
            if freq >= filterFreq-margin and freq > maxFrequency[pos]:
                maxFrequency[pos] = freq
                key[pos] = msgBytes[pos]^ord(' ')
    return key

def numberOfMsgs(ciphertexts, pos):
    pos = 2*pos #hexadecimal
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

