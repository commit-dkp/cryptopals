# CryptoPals Python Solutions / Set 3 / Solution 24
# Challenge in 24-create-the-mt19937-stream-cipher-and-break-it.md .
#
# This challenge is a bit odd because it's really just Challenge 22 but with more steps. Once again, you see how
# important it is that your key/seed is not discoverable, by being both large and unpredictable. The CryptMT cipher is
# interesting, and while it was a finalist in the eSTREAM standards process, it was not selected for the final portfolio
# and so you should not expect to find it in use. https://www.ecrypt.eu.org/stream/portfolio.pdf explains further.
from Crypto.Util.number import long_to_bytes
from random import Random
from secrets import choice, randbelow, randbits, token_bytes
from string import printable
from time import time

SMALL_MIN = 16
CRYPTMT_MIN = 16


def small_oracle(plaintext):
    key = randbits(SMALL_MIN)
    key = key.to_bytes(CRYPTMT_MIN, 'big')
    plaintext_len = len(plaintext)
    prefix_len = randbelow(plaintext_len) + 1
    prefix = ''
    for _ in range(prefix_len):
        prefix = prefix + choice(printable)
    plaintext = prefix + plaintext
    return crypt_mt(key, plaintext.encode())


def timestamp_oracle():
    key = time()
    key = int(key).to_bytes(CRYPTMT_MIN, 'big')
    token = b'\x00' * 16
    return crypt_mt(key, token)


# "Cryptographic Mersenne Twister and Fubuki Stream/Block Cipher" at https://eprint.iacr.org/2005/165.pdf .
def crypt_mt(key, in_text, iv=None):
    key_len = len(key)
    max_size = 256
    if (0 >= key_len > max_size) or (key_len % CRYPTMT_MIN != 0):
        raise ValueError
    if iv is None:
        iv = token_bytes(max_size)
        mode = 'encrypt'
    else:
        iv_len = len(iv)
        if (0 >= iv_len > max_size) or (iv_len % CRYPTMT_MIN != 0):
            raise ValueError
        mode = 'decrypt'
    mt = Random()
    seed = key + iv
    mt.seed(seed)
    width = 32
    # "To raise the security, the first 64 bytes of the outputs are discarded."
    discard = 64 // (width // 8)
    accum = 1
    for out_byte in range(discard):
        gotrandbits = mt.getrandbits(width)
        accum = accum * gotrandbits
    out_text = b''
    for out_byte in in_text:
        gotrandbits = mt.getrandbits(width)
        accum = accum * gotrandbits
        out_byte = out_byte ^ long_to_bytes(accum)[0]
        out_text = out_text + bytes([out_byte])
    if mode == 'encrypt':
        return iv, out_text
    return out_text


def main():
    # Attack the small key.
    known_text = 'AAAAAAAAAAAAAA'
    iv, ciphertext = small_oracle(known_text)
    # You could easily increase the range to attack larger keys up to 56 bits.
    for key in range(2 ** SMALL_MIN):
        mt_key = key.to_bytes(CRYPTMT_MIN, 'big')
        plaintext = crypt_mt(mt_key, ciphertext, iv)
        if known_text.encode() in plaintext:
            print(f'Small Key: {key:#02x}')
            break
    # Attack the timestamp key, again, just like in Challenge 22. Unix timestamps are the number of seconds since
    # 1970-01-01T00:00:00Z.
    start = time()
    # Since the timestamp oracle always returns a 2304-bit ciphertext (2048-bit random IV + 256-bit random token), you
    # can assume that as some systems do, the IV is returned separate from the ciphertext and does not need to be
    # discovered.
    iv, ciphertext = timestamp_oracle()
    stop = time()
    start = int(start)
    stop = int(stop)
    # The token is randomly generated, so when "decrypted" it is merely the same size of zero-bytes.
    token = b'\x00' * len(ciphertext)
    for candidate in range(start, stop + 1):
        candidate = candidate.to_bytes(CRYPTMT_MIN, 'big')
        plaintext = crypt_mt(candidate, ciphertext, iv)
        if token == plaintext:
            key = int.from_bytes(candidate, 'big')
            print(f'Timestamp Key: {key}')
            break


if __name__ == '__main__':
    main()
