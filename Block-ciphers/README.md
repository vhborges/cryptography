# Block-Ciphers
Block-Cipher is a type of encryption scheme in which the plaintext to be encrypted is divided into blocks of the same length, and each block is encrypted separately.

Suppose you have the plaintext "Cryptography is awesome" and you want to encrypt it using a block-cipher with blocks of length 8, so each block would be:<br>
1 - "Cryptogr"<br>
2 - "aphy is "<br>
3 - "awesome"

Obs: the last block doesn't have the correct length, we'll deal with that later...

**Attention:** DO NOT use any code in this repository to encrypt sensitive data. This was only made for educational purposes and is NOT secure for real life encryption.

In this Block-Cipher code I've used the [Feistel Network](https://en.wikipedia.org/wiki/Feistel_cipher) as a encryption structure and I've created a very simple function for the Feistel Network that does a XOR between the input and the key to generate "confusion", and later shuffles all the bytes to generate "diffusion". Again, this is NOT a secure function.

## Modes of operation
There are multiple ways of encrypting each block and unifying the result into a ciphertext, these "ways" are called modes of operation.

To learn more about modes of operation, this Wikipedia page covers the main ones pretty well: [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation).

This section I've implemented and will cover three modes: ECB, CBC and PCBC.

Some Modes of Operating requires that each block should be of the same lenght, so when the last block does not fit into a whole block, we need to add a "padding" in the end. Suppose we need to add 6 bytes to the end of a block, the common way to do this is by adding the byte "x06" 6 times, this facilitates the process of identifying what is just a padding and what is the actual plaintext, so that we can decrypt the ciphertext correctly.

## Avalanche Effect
The Avalanche Effect is a property of some algorithms and encryption schemes in which small changes in the input (on our case, the plainext) generates huge changes in the output (on our case, the ciphertext).

This is a desirable property, since we want our encryption schemes to leak as little information about the plaintext as possible.

The encryption algorithm used to encrypt one block dictates if the output of that specific block will have the Avalanche Effect. But between different blocks, we need to use a Mode of Operation that also has this property to ensure that, for example, a change in the first block will propagate to all blocks.

In the three modes of operation mentioned in the section above, ECB is the only scheme that does not have the Avalanche Effect.

To see the Avalanche Effect in action, run the `avalanche_effect.py` script. Notice the bytes of the ciphertext before and after the plaintext has been modified.

## Bit-flipping
Bit-flipping is an attack on some Modes of Operation that use an IV (initialization vector), like CBC. It also can be used on Stream-Ciphers, on which the attack is even stronger.

This attack consists in changing some bytes of the IV (usually the first block of the ciphertext) in a way that, when it gets decrypted, the plaintext will have some bytes modified in a predictable way!

Suppose we have the plaintext "you owe me $10000". By this attack, we can change the middle zero to a dot, so that when the corresponding ciphertext gets to it's destination, it will be decrypted to "you owe me $10.00".

To see this in action, study and run the `bit_flipping.py` script.
