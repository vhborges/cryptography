from os import urandom

def randomBytes(size):
    return urandom(size)

def readFile(filename):
    with open(filename) as file:
        ciphertexts = file.read().splitlines()
    return ciphertexts

def writeFile(filename, list_):
    with open(filename, 'w') as file:
        for item in list_:
            file.write(f'{item}\n')

def printList(l):
    for pos, item in enumerate(l):
        print(f'{pos}. {item}')

def xorBytes(msg1, msg2):
    return bytes(a^b for a, b in zip(msg1, msg2))

