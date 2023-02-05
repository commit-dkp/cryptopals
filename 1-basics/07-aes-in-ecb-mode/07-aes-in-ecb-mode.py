# CryptoPals Python Solutions / Set 1 / Solution 7
# Challenge in 07-aes-in-ecb-mode.md .
#
# A demonstration of how to use the Pycryptodome library's AES implementation. If you'd like an extra challenge, go
# ahead and write your own AES code, but it won't be necessary to reuse your code for the rest of the exercises.
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def main():
    key = 'YELLOW SUBMARINE'
    aes_ecb = AES.new(key.encode(), AES.MODE_ECB)
    with open('7.txt', 'r') as file:
        ciphertext = b64decode(file.read())
    plaintext = aes_ecb.decrypt(ciphertext)
    plaintext = unpad(plaintext, AES.block_size)
    filename = '7-plaintext.txt'
    with open(f'{filename}', 'wb') as file:
        file.write(plaintext)
    print(f'Wrote {filename}!')


if __name__ == '__main__':
    main()
