# CryptoPals Python Solutions / Set 3 / Solution 20
# Challenge in 20-break-fixed-nonce-ctr-statistically.md .
#
# As CTR repeats the key stream it XORs across plaintext when the nonce is fixed, you can modify the solution from
# Challenge 6. As in Challenge 19, use plaintext from the shortest ciphertext to help you make a crib for the longest
# ciphertext.
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_CTR
from pwnlib.util.fiddling import xor
from secrets import token_bytes
from sys import float_info


def oracle():
    key = token_bytes(AES.block_size)
    nonce = b'\x00' * (AES.block_size // 2)
    ciphertexts = []
    with open('20.txt') as file:
        for based in file:
            aes_ctr = AES.new(key, MODE_CTR, nonce=nonce)
            plaintext = b64decode(based)
            ciphertext = aes_ctr.encrypt(plaintext)
            ciphertexts.append(aes_ctr.nonce + ciphertext)
    return ciphertexts


def main():
    # Test that the oracle's output is from a stream cipher.
    ciphertexts = oracle()
    ciphertexts_len = len(ciphertexts)
    ciphertexts_sizes = set()
    for ciphertext in ciphertexts:
        ciphertext_len = len(ciphertext)
        ciphertexts_sizes.add(ciphertext_len)
    ciphertexts_sizes = sorted(ciphertexts_sizes, reverse=True)
    try:
        for index in range(ciphertexts_len - 1):
            # There must be a difference in size of one byte.
            if ciphertexts_sizes[index] - ciphertexts_sizes[index + 1] == 1:
                raise StopIteration
        print('Probably not a stream cipher!')
        return
    except StopIteration:
        pass
    # For a fixed nonce, the first n bytes are the same for all ciphertexts.
    shortest = min(ciphertexts, key=len)
    shortest_len = len(shortest)
    nonce_len = 0
    try:
        for index_1 in range(shortest_len):
            for index_2 in range(ciphertexts_len - 1):
                if ciphertexts[index_2][index_1] != ciphertexts[index_2 + 1][index_1]:
                    raise StopIteration
            nonce_len = nonce_len + 1
    except StopIteration:
        pass
    if nonce_len == 0:
        print('No nonce?!')
        return
    # Remove the nonce from the ciphertexts.
    for index in range(ciphertexts_len):
        ciphertexts[index] = ciphertexts[index][nonce_len:]
    # Break it! By default, zip() stops when the shortest ciphertext is exhausted.
    chunks = []
    for cipherbyte in zip(*ciphertexts):
        column = list(cipherbyte)
        chunks.append(column)
    key = b''
    for chunk in chunks:
        byte_value_max = 0xff
        # https://web.archive.org/web/20200205183157/www.data-compression.com/english.html
        char_freqs = {'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881,
                      'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
                      'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563,
                      's': 0.0515760, 't': 0.0729357, 'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
                      'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}
        keybyte_scored = float_info.max
        keybyte_candidate = 0
        for candidate in range(byte_value_max):
            candidate = bytes([candidate])
            plaintext = xor(candidate, chunk)
            try:
                plaintext_lower = plaintext.decode().lower()
            except UnicodeError:
                continue
            char_counts = {}
            for char in plaintext_lower:
                if char in char_counts:
                    char_counts[char] = char_counts[char] + 1
                else:
                    char_counts[char] = 1
            score_default = 0.0000001
            scored = 0.0
            for char in char_counts.keys():
                observed = char_counts[char]
                expected = len(plaintext) * char_freqs.get(char, score_default)
                difference = observed - expected
                chi_squared = (difference * difference) / expected
                scored = scored + chi_squared
            if scored < keybyte_scored:
                keybyte_scored = scored
                keybyte_candidate = candidate
        key = key + bytes(keybyte_candidate)
    # shortest = min(ciphertexts, key=len)
    # xor(key, shortest).decode() yields 'and count our money / Yo, well check this out, yo Eli', for which the first
    # Google result is the song "Paid In Full" by Eric B. & Rakim.
    # longest = max(ciphertexts, key=len)
    # xor(key, longest, cut='left').decode() would yield 'You want to hear some sounds that not only pounds but', for
    # which the first Google result is the song "Lyrics Of Fury" by Eric B. & Rakim.
    # Taking the rest of the longest line and combining it with the next line, as was done in the shortest plaintext,
    # yields a crib of 'You want to hear some sounds that not only pounds but please your eardrums; / I sit back and
    # observe the whole scenery'.
    crib = 'You want to hear some sounds that not only pounds but please your eardrums; / ' \
           'I sit back and observe the whole scenery'
    longest = max(ciphertexts, key=len)
    key = xor(crib.encode(), longest)
    filename = '20-plaintext.txt'
    with open(f'{filename}', 'w') as file:
        for ciphertext in ciphertexts:
            plaintext = xor(key, ciphertext, cut='right')
            print(plaintext.decode(), file=file)
    print(f'Wrote {filename}!')


if __name__ == '__main__':
    main()
