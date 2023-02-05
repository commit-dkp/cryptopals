# CryptoPals Python Solutions / Set 2 / Solution 10
# Challenge in 10-implement-cbc-mode.md .
#
# This challenge insists on writing your own CBC decrypt code, but it won't be necessary to reuse it for the rest of the
# exercises, and it is especially unnecessary to write CBC encrypt code. For the rest of the exercises, you can use the
# Pycryptodome library's CBC implementation.
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pwnlib.util.fiddling import xor
from pwnlib.util.lists import group


def main():
    key = 'YELLOW SUBMARINE'
    aes_ecb = AES.new(key.encode(), AES.MODE_ECB)
    # The IV is normally included as the first ciphertext block, but CryptoPals has excluded it from this ciphertext. It
    # is not a secret value, but it does need to be unpredictably chosen.
    iv = b'\x00' * AES.block_size
    with open('10.txt', 'r') as file:
        ciphertext = b64decode(file.read())
    ciphertext = iv + ciphertext
    blocks = group(AES.block_size, ciphertext)
    blocks_len = len(blocks)
    plaintext = b''
    # ECB-decrypt the second block, XOR it with the previous block (which is the IV), save the now-plaintext block and
    # move on to the next ciphertext block until the last one is turned into plaintext.
    for index in range(blocks_len - 1):
        decrypt = aes_ecb.decrypt(blocks[index + 1])
        plaintext = plaintext + xor(decrypt, blocks[index])
    plaintext = unpad(plaintext, AES.block_size)
    filename = '10-plaintext.txt'
    with open(f'{filename}', 'wb') as file:
        file.write(plaintext)
    print(f'Wrote {filename}!')


if __name__ == '__main__':
    main()
