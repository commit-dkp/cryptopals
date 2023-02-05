# CryptoPals Python Solutions / Set 2 / Solution 11
# Challenge in 11-an-ecb-cbc-detection-oracle.md .
#
# Since the same 16 byte plaintext block will always produce the same 16 byte ciphertext ECB block, all you need to do
# is submit a plaintext that is guaranteed to contain a repeated block. If there's no repeated ciphertext block, then it
# wasn't encrypted in ECB mode. However, block sizes are not defined by the block mode but by the block cipher, so you
# can't just assume a block size of 16 bytes.
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwnlib.util.lists import group
from secrets import choice, randbelow, token_bytes


def oracle_encrypt(plaintext):
    if len(plaintext) == 0:
        raise ValueError
    key = token_bytes(AES.block_size)
    mode = choice([AES.MODE_ECB, AES.MODE_CBC])
    aes_chosen = AES.new(key, mode)
    append_max = 10
    append_min = 5
    append_count = append_max - randbelow(append_max - append_min + 1)
    append = bytes([append_count]) * append_count
    plaintext = append + plaintext + append
    plaintext = pad(plaintext, AES.block_size)
    if mode == AES.MODE_ECB:
        return aes_chosen.encrypt(plaintext)
    else:
        return aes_chosen.iv + aes_chosen.encrypt(plaintext)


def main():
    query = 'A'
    # At 512 bytes, http://www.ciphergoth.org/crypto/mercy/ is the largest block cipher I know, and N-byte blocks will
    # repeat even if the block size is less than N.
    block_size = 512
    block = query * block_size
    # Accounting for the possibility of a prefix, three blocks is necessary to force one repetition.
    block_count = 3
    query_mode = block * block_count
    ciphertext = oracle_encrypt(query_mode.encode())
    blocks = group(block_size, ciphertext)
    blocks_len = len(blocks)
    # CBC mode isn't actually distinguishable by the chosen-plaintext attack here, as it could be some other mode like
    # CTR, but in a later challenge CBC is distinguishable by non-adaptive chosen ciphertext attacks!
    for index in range(blocks_len - 1):
        if blocks[index] == blocks[index + 1]:
            print('ECB: repeated block!')
            return
    print('Not ECB: no repeated block!')


if __name__ == '__main__':
    main()
