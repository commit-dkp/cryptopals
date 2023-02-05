# CryptoPals Python Solutions / Set 1 / Solution 2
# Challenge in 02-fixed-xor.md .
#
# A demonstration of how to use the pwntools library's XOR implementation. If you'd like an extra challenge, go ahead
# and write your own XOR code, but it won't be necessary to reuse your code for the rest of the exercises.
from pwnlib.util.fiddling import xor


def main():
    # "hit the bull's eye".encode().hex()
    key = '686974207468652062756c6c277320657965'
    key = bytes.fromhex(key)
    ciphertext = '1c0111001f010100061a024b53535009181c'
    ciphertext = bytes.fromhex(ciphertext)
    plaintext = xor(key, ciphertext)
    # "the kid don't play".encode().hex()
    print(plaintext.hex())


if __name__ == '__main__':
    main()
