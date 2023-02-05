# CryptoPals Python Solutions / Set 1 / Solution 3
# Challenge in 03-single-byte-xor-cipher.md .
#
# For every possible key, decrypt the ciphertext and chi-square test the candidate. Whichever candidate had the lowest
# chi-squared value is the most likely plaintext. It might not actually be English, but this is good enough! More at
# http://practicalcryptography.com/cryptanalysis/text-characterisation/chi-squared-statistic/ .
from pwnlib.util.fiddling import xor
from sys import float_info


def main():
    byte_value_max = 0xff
    # https://web.archive.org/web/20200205183157/www.data-compression.com/english.html
    char_freqs = {'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881,
                  'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
                  'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563,
                  's': 0.0515760, 't': 0.0729357, 'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
                  'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}
    plaintext_scored = float_info.max
    plaintext_candidate = b''
    ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    ciphertext = bytes.fromhex(ciphertext)
    for key_byte in range(byte_value_max + 1):
        key = bytes([key_byte])
        candidate = xor(key, ciphertext)
        try:
            candidate_lower = candidate.decode().lower()
        except UnicodeError:
            continue
        char_counts = {}
        for char in candidate_lower:
            if char in char_counts:
                char_counts[char] = char_counts[char] + 1
            else:
                char_counts[char] = 1
        score_default = 0.0000001
        scored = 0.0
        for char in char_counts.keys():
            observed = char_counts[char]
            expected = len(candidate) * char_freqs.get(char, score_default)
            difference = observed - expected
            chi_squared = (difference * difference) / expected
            scored = scored + chi_squared
        if scored < plaintext_scored:
            plaintext_scored = scored
            plaintext_candidate = candidate
    print(plaintext_candidate.decode())


if __name__ == '__main__':
    main()
