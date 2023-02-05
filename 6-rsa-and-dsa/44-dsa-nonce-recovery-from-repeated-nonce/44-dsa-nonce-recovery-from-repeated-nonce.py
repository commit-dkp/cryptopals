# CryptoPals Python Solutions / Set 6 / Solution 44
# Challenge in 44-dsa-nonce-recovery-from-repeated-nonce.md .
#
# Repeated nonces in asymmetric cryptography can be just as bad as they are in symmetric cryptography. Repeat a nonce
# with a stream cipher, and the adversary can recover partial keystream; repeat a nonce with DSA, and the adversary can
# recover the private key! When cryptographers say "nonce", they mean it, but alas in the DSA specification at
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf it is called a "per-message secret number" and so a lot of
# implementations have gotten this wrong.
from Crypto.Hash import SHA1
from itertools import combinations
from re import findall
from secrets import randbelow


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
            if sig_r == 0:
                continue
            secret_inv = pow(secret, -1, self.prime_divisor)
            leftmost = min(self.prime_divisor.bit_length(), SHA1.digest_size * 8)
            hashed = SHA1.new(message).digest()[:leftmost]
            hashed = int.from_bytes(hashed, 'big')
            hashed = hashed + self.private_key * sig_r
            sig_s = (secret_inv * hashed) % self.prime_divisor
            if sig_s != 0:
                return sig_r, sig_s

    def verify(self, public_key, message, sig_r, sig_s):
        if not (0 < sig_r < self.prime_divisor) or not (0 < sig_s < self.prime_divisor):
            return False
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
    # "The Digital Signature Algorithm (DSA) is no longer specified in this standard and may only be used to verify
    # previously generated digital signatures."
    message = 'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf'
    sig_r, sig_s = dsa.sign(message.encode())
    if not dsa.verify(dsa.public_key, message.encode(), sig_r, sig_s):
        print('Signing/verifying is broken?!')
    # Break it!
    pattern = r'msg: [a-zA-Z.,\' ]+\n' \
              r's: ([0-9]+)\n' \
              r'r: ([0-9]+)\n' \
              r'm: ([0-9a-f]+)\n?'
    public_key = int('2d026f4bf30195ede3a088da85e398ef869611d0f68f07'
                     '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8'
                     '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519'
                     'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430'
                     'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3'
                     '2971c3de5084cce04a2e147821', 16)
    private_hash = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
    with open('44.txt', 'r') as file:
        messages = file.read()
    messages = findall(pattern, messages)
    pairs = combinations(messages, 2)
    for (message_1, message_2) in pairs:
        r_1, r_2 = int(message_1[1]), int(message_2[1])
        if r_1 == r_2:
            m_1, m_2 = int(message_1[2], 16), int(message_2[2], 16)
            m_3 = m_1 - m_2
            s_1, s_2 = int(message_1[0]), int(message_2[0])
            s_3 = s_1 - s_2
            s_3 = pow(s_3, -1, dsa.prime_divisor)
            secret = (m_3 * s_3) % dsa.prime_divisor
            m_3 = (s_1 * secret) - m_1
            r_3 = pow(r_1, -1, dsa.prime_divisor)
            private_key = (m_3 * r_3) % dsa.prime_divisor
            if public_key == pow(dsa.generator, private_key, dsa.prime_modulus):
                private_key = hex(private_key)[2:]
                # With DSA, there is only one public key which matches a given private key, provided that the key pair was
                # correctly generated. But just in case, check against the known hash of the private key.
                if private_hash == SHA1.new(private_key.encode()).hexdigest():
                    print(f'Private key: {private_key}')
                    break


if __name__ == '__main__':
    main()
