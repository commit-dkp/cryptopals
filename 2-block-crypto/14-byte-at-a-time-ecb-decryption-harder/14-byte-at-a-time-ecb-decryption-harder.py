# CryptoPals Python Solutions / Set 2 / Solution 14
# Challenge in 14-byte-at-a-time-ecb-decryption-harder.md .
#
# What's harder about this challenge is that there's a good chance the oracle will prepend a random-but-fixed amount of
# bytes to your plaintext. You will need to learn the length of this prefix to ensure your plaintext is aligned on a
# block boundary, and that you are comparing the right blocks for equality. Of course, this solution also works for when
# there is _no_ prefix (as might be the case here), but it is not as "simple". If you would like an extra challenge, how
# could you break it if the prefix was generated for every query? It'll take a lot more queries, for sure!
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwnlib.util.lists import group
from secrets import randbelow, token_bytes
from string import printable


class Oracle:
    key = token_bytes(AES.block_size)
    unknown = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFu\
               ZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    unknown = b64decode(unknown)
    # Interpreting "a random count of random bytes" as "a random count of less than a kilobyte".
    prefix_len = randbelow(1000)
    prefix = token_bytes(prefix_len)

    def encrypt(self, plaintext):
        if len(plaintext) == 0:
            raise ValueError
        aes_ecb = AES.new(self.key, AES.MODE_ECB)
        plaintext = self.prefix + plaintext + self.unknown
        plaintext = pad(plaintext, AES.block_size)
        return aes_ecb.encrypt(plaintext)


def main():
    oracle = Oracle()
    query = 'A'
    ciphertext = oracle.encrypt(query.encode())
    initial_len = len(ciphertext)
    current_len = initial_len
    # At 512 bytes, http://www.ciphergoth.org/crypto/mercy/ is the largest block cipher I know.
    block_size_max = 512
    query_size = query
    for _ in range(block_size_max + 1):
        query_size = query_size + query
        ciphertext = oracle.encrypt(query_size.encode())
        current_len = len(ciphertext)
        if current_len != initial_len:
            break
    block_size = current_len - initial_len
    if block_size <= 1:
        print('Probably not a block cipher!')
        return
    # Accounting for the possibility of a prefix, three blocks would be enough to force one repetition. Since you also
    # need to account for the probability of small-sized blocks repeating randomly, ask for four blocks and look for two
    # repetitions!
    block = query * block_size
    block_count = 4
    query_mode = block * block_count
    ciphertext = oracle.encrypt(query_mode.encode())
    blocks = group(block_size, ciphertext)
    blocks_len = len(blocks)
    try:
        for index in range(blocks_len - 2):
            if blocks[index] == blocks[index + 1] and blocks[index] == blocks[index + 2]:
                raise StopIteration
        print('Not ECB mode?!')
        return
    except StopIteration:
        pass
    # Query the oracle to determine which block the fixed prefix stops at.
    query_1 = query
    ciphertext_1 = oracle.encrypt(query_1.encode())
    blocks_1 = group(block_size, ciphertext_1)
    query_2 = 'B'
    ciphertext_2 = oracle.encrypt(query_2.encode())
    blocks_2 = group(block_size, ciphertext_2)
    blocks_len = len(blocks_2)
    prefix_start = 0
    for index in range(blocks_len):
        if blocks_1[index] != blocks_2[index]:
            prefix_start = index * block_size
            break
    # Query the oracle to determine which byte the fixed prefix stops at.
    byte_len = 0
    prefix_end = prefix_start + block_size
    for index in range(1, block_size):
        query_1 = query * index
        candidate_1 = oracle.encrypt(query_1.encode())[prefix_start:prefix_end]
        query_2 = query_1 + query
        candidate_2 = oracle.encrypt(query_2.encode())[prefix_start:prefix_end]
        if candidate_1 == candidate_2:
            byte_len = len(query_1)
            break
    prefix_len = prefix_start + (block_size - byte_len)
    # Break it!
    remainder = 0
    fill = b''
    if prefix_len % block_size:
        remainder = block_size - (prefix_len % block_size)
        fill = query * remainder
    plaintext = b''
    window_start = prefix_len + remainder + block_size
    window = block_size
    byte_value_max = 0xff
    while True:
        plaintext_len = len(plaintext)
        window_len = block_size - (plaintext_len % block_size) - 1
        query_window = fill + (query * block_size) + (query * window_len)
        window_end = window_start + window
        initial_ciphertext = oracle.encrypt(query_window.encode())[window_start:window_end]
        found = False
        for byte in range(byte_value_max + 1):
            byte = bytes([byte])
            candidate = oracle.encrypt(query_window.encode() + plaintext + byte)[window_start:window_end]
            if initial_ciphertext == candidate:
                plaintext = plaintext + byte
                found = True
                break
        if found:
            if len(plaintext) % block_size == 0:
                window = window + block_size
        else:
            printtext = ''
            for char in plaintext:
                char = chr(char)
                if char in printable:
                    printtext = printtext + char
            print(f'{printtext.rstrip()}')
            break


if __name__ == '__main__':
    main()
