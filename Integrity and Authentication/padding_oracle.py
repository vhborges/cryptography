import urllib.request
import sys

TARGET = 'http://crypto-class.appspot.com/po?er='

#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------

def query(q):
    target = TARGET + urllib.request.quote(q)    # Create query URL
    req = urllib.request.Request(target)         # Send HTTP request to server
    try:
        f = urllib.request.urlopen(req)          # Wait for response
    except urllib.request.HTTPError as e:
        print("We got: %d" % e.code)       # Print response code
        if e.code == 404:
            return 1 # good padding
        return 0 # bad padding
    return 2 # correct ciphertext

if __name__ == "__main__":
    ciphertext = bytes.fromhex('f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4')

    tam_bloco = 16

    ultimo_bloco = (len(ciphertext) // tam_bloco) - 2

    chutes_global = []

    for bloco in range(ultimo_bloco, -1, -1):
        ciphertext = ciphertext[:tam_bloco*(bloco+2)]
        chutes = []
        for byte in range(tam_bloco - 1, -1, -1):
            byte_pad = tam_bloco - byte
            ciphertext_ = bytearray(ciphertext)
            for pos in range(byte + 1, tam_bloco):
                pos_chute = tam_bloco - 1 - pos
                print('byte:',byte,'pos:',pos,'byte_pad:',byte_pad,'pos_chute:',pos_chute,'\nchutes:',chutes)
                ciphertext_[tam_bloco * bloco + pos] ^= chutes[pos_chute] ^ byte_pad
            for chute in range(256):
                _ciphertext = ciphertext_[:]
                _ciphertext[tam_bloco * bloco + byte] ^= chute ^ byte_pad
                result = query(_ciphertext.hex())
                if (result == 1) or (result == 2 and byte != tam_bloco - 1):
                    chutes.append(chute)
                    break
            else:
                print('deu ruim')
        chutes_global.extend(chutes)

    plaintext = bytes(reversed(chutes_global))

    print(plaintext)
