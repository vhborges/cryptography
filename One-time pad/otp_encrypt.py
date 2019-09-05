import os

MSGS = ("message 1",\
        "message 2",\
        "message 3",\
        "message 4",\
        "message 5",\
        "message 6",\
        "message 7",\
        "message 8",\
        "message 9",\
        "message 10")

def bytexor(a, b):
    return bytes(x^y for x, y in zip(a, b))

def random(size=16):
    return os.urandom(size)

def encrypt(key, msg):
    msg = bytes(msg, 'ascii')
    c = bytexor(key, msg)
    print(c.hex())
    return c

key = random(max(len(msg) for msg in MSGS))
ciphertexts = [encrypt(key, msg) for msg in MSGS]
