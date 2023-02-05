# CryptoPals Python Solutions / Set 5 / Solution 39
# Challenge in 39-implement-rsa.md .
#
# Pycryptodome doesn't implement "textbook" no-padding RSA, but you can still use it to more easily generate strong
# primes. You could also use it to do the whole key-pair generation, but where's the fun in that? For a highly
# accessible explanation of how all the moving parts of RSA work together, check out "RSA: implementation and proofs" at
# https://sevko.io/articles/rsa/ .
from Crypto.Util.number import getStrongPrime, long_to_bytes
from secrets import choice


class TextbookRSA:
    def __init__(self):
        prime_len = 512
        # It is more common to see e = 65537 as the fastest, largest prime with which to raise an unpadded message. If
        # the message is securely padded, e = 3 is less of a problem, but cryptographers prefer to hedge their bet
        # against a weakness in the padding scheme. Except in https://cr.yp.to/sigs/rwsota-20080131.pdf , where it is
        # argued that e = 2 is provably safe and of course faster than e = 3.
        self.public_exponent = 3
        p_prime = getStrongPrime(N=prime_len, e=self.public_exponent)
        q_prime = getStrongPrime(N=prime_len, e=self.public_exponent)
        self.composite = p_prime * q_prime
        self.phi = (p_prime - 1) * (q_prime - 1)
        self.private_exponent = pow(self.public_exponent, -1, self.phi)
        self.composite_len = (prime_len // 8) * 2

    def encrypt(self, plaintext):
        plaintext = int.from_bytes(plaintext, 'big')
        ciphertext = pow(plaintext, self.public_exponent, self.composite)
        return ciphertext.to_bytes(self.composite_len, 'big')

    def decrypt(self, ciphertext):
        ciphertext = int.from_bytes(ciphertext, 'big')
        plaintext = pow(ciphertext, self.private_exponent, self.composite)
        return long_to_bytes(plaintext)


def main():
    alice = TextbookRSA()
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    plaintext = choice(words_split)
    ciphertext = alice.encrypt(plaintext.encode())
    decrypt = alice.decrypt(ciphertext)
    if decrypt == plaintext.encode():
        print(f'{plaintext}!')
    else:
        print('Decrypt failed?!')


if __name__ == '__main__':
    main()
