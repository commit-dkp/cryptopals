# CryptoPals Python Solutions / Set 3 / Solution 18
# Challenge in 18-implement-ctr-the-streaming-cipher-mode.md .
#
# This challenge insists on writing your own CTR code, but it won't be necessary to reuse your code for the rest of the
# exercises, where you can use the Pycryptodome library's CTR implementation.
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_ECB
from pwnlib.util.fiddling import xor
from pwnlib.util.lists import group


def main():
    based = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    debased = b64decode(based)
    blocks = group(AES.block_size, debased)
    blocks_len = len(blocks)
    counter = 0
    half_block = AES.block_size // 2
    key = 'YELLOW SUBMARINE'
    aes_ecb = AES.new(key.encode(), MODE_ECB)
    nonce = b'\x00' * half_block
    plaintext = b''
    for index in range(blocks_len):
        counter_bytes = counter.to_bytes(half_block, 'little')
        key_stream = aes_ecb.encrypt(nonce + counter_bytes)
        # Passing cut='right' is necessary for when the last ciphertext bytes are smaller than a block.
        plain = xor(key_stream, blocks[index], cut='right')
        plaintext = plaintext + plain
        counter = counter + 1
    print(plaintext.decode())


if __name__ == '__main__':
    main()
