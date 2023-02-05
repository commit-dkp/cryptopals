# CryptoPals Python Solutions / Set 1 / Solution 5
# Challenge in 05-implement-repeating-key-xor.md .
#
# A demonstration of how to use the pwntools library's XOR implementation. If you'd like an extra challenge, go ahead
# and modify your own XOR code, but it won't be necessary to reuse your code for the rest of the exercises.
from pwnlib.util.fiddling import xor


def main():
    key = 'ICE'
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ciphertext = xor(key.encode(), plaintext.encode())
    print(ciphertext.hex())


if __name__ == '__main__':
    main()
