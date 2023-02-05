# CryptoPals Python Solutions / Set 2 / Solution 12
# Challenge in 12-byte-at-a-time-ecb-decryption-simple.md .
#
# For every byte in the unknown ciphertext, submit an ever-shrinking query. For each printable character, re-submit
# another query appended with any recovered plaintext and this character, until the oracle's response matches this
# byte's shrunk query response. Append that printable character to the known plaintext, and repeat until every byte is
# recovered.
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwnlib.util.lists import group
from secrets import token_bytes
from string import printable


class Oracle:
    key = token_bytes(AES.block_size)
    unknown = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFu\
               ZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    unknown = b64decode(unknown)

    def encrypt(self, plaintext):
        if len(plaintext) == 0:
            raise ValueError
        aes_ecb = AES.new(self.key, AES.MODE_ECB)
        plaintext = plaintext + self.unknown
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
    # Break it!
    plaintext = b''
    window_start = block_size
    window = block_size
    byte_value_max = 0xff
    while True:
        plaintext_len = len(plaintext)
        window_len = block_size - (plaintext_len % block_size) - 1
        query_window = (query * block_size) + (query * window_len)
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
