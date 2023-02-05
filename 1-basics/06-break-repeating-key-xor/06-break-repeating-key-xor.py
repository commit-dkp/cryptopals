# CryptoPals Python Solutions / Set 1 / Solution 6
# Challenge in 06-break-repeating-key-xor.md .
#
# The trick here is transposing the repeating-key ciphertext into chunks that are scored like single-byte XOR
# ciphertext. While the chunks could only decrypt into English by random chance, the character frequencies for the
# chi-squared test still hold.
from base64 import b64decode
from pwnlib.util.fiddling import bits, xor
from pwnlib.util.lists import group
from sys import float_info


def main():
    keysize_min = 2
    keysize_max = 40
    with open('6.txt', 'r') as file:
        ciphertext = b64decode(file.read())
    keysize_distance = float_info.max
    keysize_candidate = 0
    # Find the key size by measuring Hamming distance. The works because the expected Hamming distance between two
    # random English letters is at most 3 bits, whereas for two random bytes it is 4 bits. So the Hamming distance
    # between two random English letters XORd by the same byte is still at most 3 bits, but 4 bits if they were XORd by
    # different bytes.
    for candidate in range(keysize_min, keysize_max + 1):
        ciphertext_chunks = group(candidate, ciphertext, 'drop')
        ciphertext_chunks_range = len(ciphertext_chunks) - 1
        distance_total = 0
        for index in range(ciphertext_chunks_range):
            xord = xor(ciphertext_chunks[index], ciphertext_chunks[index + 1])
            distance = bits(xord).count(1)
            distance_total = distance_total + distance
        distance_normalized = distance_total / ciphertext_chunks_range / candidate
        if keysize_distance > distance_normalized:
            keysize_candidate = candidate
            keysize_distance = distance_normalized
    chunks = []
    # Transpose and chunk the ciphertext at the same time.
    for index in range(keysize_candidate):
        chunks.append(ciphertext[index::keysize_candidate])
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
        for key_byte in range(byte_value_max + 1):
            byte_guess = bytes([key_byte])
            candidate = xor(byte_guess, chunk)
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
            if scored < keybyte_scored:
                keybyte_scored = scored
                keybyte_candidate = byte_guess
        key = key + bytes(keybyte_candidate)
    # 'Terminator X: Bring the noise'.encode()
    plaintext = xor(key, ciphertext)
    filename = '6-plaintext.txt'
    with open(f'{filename}', 'wb') as file:
        file.write(plaintext)
    print(f'Wrote {filename}!')


if __name__ == '__main__':
    main()
