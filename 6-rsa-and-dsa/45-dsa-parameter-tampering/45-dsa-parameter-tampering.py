# CryptoPals Python Solutions / Set 6 / Solution 45
# Challenge in 45-dsa-parameter-tampering.md .
#
# Since the DSA is based on the same discrete logarithm problem that Diffie-Hellman is based on, it suffers from the
# same risks of maliciously chosen parameters influencing the verification of signatures. To explore those risks in more
# depth, check out "The Security Of DSA And ECDSA" by Serge Vaudenay at
# https://iacr.org/archive/pkc2003/25670309/25670309.pdf . For a safer approach, check out "Edwards-Curve Digital
# Signature Algorithm (EdDSA)" at https://datatracker.ietf.org/doc/html/rfc8032 .
from Crypto.Hash import SHA1
from secrets import choice, randbelow


class DSA:
    def __init__(self):
        self.generator = int('5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
                             '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
                             '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
                             '0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
                             '878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
                             '9fc95302291', 16)
        self.prime_divisor = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)
        self.private_key = randbelow(self.prime_divisor - 2) + 1
        self.prime_modulus = int('800000000000000089e1855218a0e7dac38136ffafa72eda7'
                                 '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
                                 '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
                                 'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
                                 'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
                                 '1a584471bb1', 16)
        self.public_key = pow(self.generator, self.private_key, self.prime_modulus)

    def sign(self, message):
        while True:
            secret = randbelow(self.prime_divisor - 2) + 1
            sig_r = pow(self.generator, secret, self.prime_modulus) % self.prime_divisor
            # if sig_r == 0:
            #     continue
            secret_inv = pow(secret, -1, self.prime_divisor)
            leftmost = min(self.prime_divisor.bit_length(), SHA1.digest_size * 8)
            hashed = SHA1.new(message).digest()[:leftmost]
            hashed = int.from_bytes(hashed, 'big')
            hashed = hashed + self.private_key * sig_r
            sig_s = (secret_inv * hashed) % self.prime_divisor
            if sig_s != 0:
                return sig_r, sig_s

    def verify(self, public_key, message, sig_r, sig_s):
        # if not (0 < sig_r < self.prime_divisor) or not (0 < sig_s < self.prime_divisor):
        #     return False
        s_inv = pow(sig_s, -1, self.prime_divisor)
        leftmost = min(self.prime_divisor.bit_length(), SHA1.digest_size * 8)
        hashed = SHA1.new(message).digest()[:leftmost]
        hashed = int.from_bytes(hashed, 'big')
        u1 = (hashed * s_inv) % self.prime_divisor
        u2 = (sig_r * s_inv) % self.prime_divisor
        t1 = pow(self.generator, u1, self.prime_modulus)
        t2 = pow(public_key, u2, self.prime_modulus)
        t3 = t1 * t2
        verifier = (t3 % self.prime_modulus) % self.prime_divisor
        return verifier == sig_r


def main():
    dsa = DSA()
    dsa.generator = 0
    dsa.public_key = pow(dsa.generator, dsa.private_key, dsa.prime_divisor)
    message = 'Hello, world!'
    sig_r, sig_s = dsa.sign(message.encode())
    print(f'generator == {dsa.generator}, r == {sig_r} !')
    if dsa.verify(dsa.public_key, message.encode(), sig_r, sig_s):
        print(f'generator == {dsa.generator}, signature is always valid!')
    dsa.generator = dsa.prime_modulus + 1
    dsa.public_key = pow(dsa.generator, dsa.private_key, dsa.prime_divisor)
    message = 'Goodbye, world!'
    sig_r, sig_s = dsa.sign(message.encode())
    if not dsa.verify(dsa.public_key, message.encode(), sig_r, sig_s):
        print(f'generator == p + 1, signature is always invalid!')
    # Generate magic signature.
    sig_r = pow(dsa.public_key, 1, dsa.prime_modulus) % dsa.prime_divisor
    sig_s = pow(1, -1, dsa.prime_divisor)
    sig_s = (sig_r * sig_s) % dsa.prime_divisor
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    word_1 = choice(words_split)
    word_2 = choice(words_split)
    if dsa.verify(dsa.public_key, word_1.encode(), sig_r, sig_s) and \
            dsa.verify(dsa.public_key, word_2.encode(), sig_r, sig_s):
        print(f'"{word_1}" and "{word_2}" both verified with the magic signature!')


if __name__ == '__main__':
    main()
