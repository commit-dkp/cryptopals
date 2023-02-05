# CryptoPals Python Solutions / Set 6 / Solution 43
# Challenge in 43-dsa-key-recovery-from-nonce.md .
#
# Pycryptodome's DSA implementation won't let you use the broken values CryptoPals requires, so you'll need to write
# your own, but at least you'll maybe reuse it for the next two challenges.
from Crypto.Hash import SHA1
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
            # Should be secret = randbelow(self.prime_divisor - 2) + 1
            secret = randbelow(2 ** 16 - 2) + 1
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
    message = 'For those that envy a MC it can be hazardous to your health\n' \
              'So be friendly, a matter of life and death, just like a etch-a-sketch\n'
    hashed = SHA1.new(message.encode()).digest()
    hashed = int.from_bytes(hashed, 'big')
    sig_s = 857042759984254168557880549501802188789837994940
    sig_r = 548099063082341131477253921760299949438196259240
    public_key = int('84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4'
                     'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004'
                     'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed'
                     '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b'
                     'bb283e6633451e535c45513b2d33c99ea17', 16)
    private_hash = '0954edd5e0afe5542a4adf012611a91912a3ec16'
    for secret in range(2 ** 16):
        private_key = sig_s * secret - hashed
        private_key = private_key * pow(sig_r, -1, dsa.prime_divisor)
        private_key = private_key % dsa.prime_divisor
        if public_key == pow(dsa.generator, private_key, dsa.prime_modulus):
            private_key = hex(private_key)[2:]
            # With DSA, there is only one public key which matches a given private key, provided that the key pair was
            # correctly generated. But just in case, check against the known hash of the private key.
            if private_hash == SHA1.new(private_key.encode()).hexdigest():
                print(f'Private key: {private_key}')
                break


if __name__ == '__main__':
    main()
