# CryptoPals Python Solutions / Set 6 / Solution 41
# Challenge in 41-implement-unpadded-message-recovery-oracle.md .
#
# Textbook RSA is homomorphic, in that operations performed on the ciphertext are applied to the plaintext as well; if
# you take some ciphertext-as-integer and multiply it by 2, and then decrypt this new ciphertext, the result will be the
# plaintext-as-integer also multiplied by 2. A secure padding scheme ensures that any such operations on the ciphertext
# results in garbage plaintext, but in its absence, you can ask the oracle to decrypt a modified ciphertext and then
# reverse the modification on the oracle's output to recover the plaintext.
from Crypto.Util.number import getStrongPrime, long_to_bytes


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


class Oracle(TextbookRSA):
    def encrypted(self):
        plaintext = "{ time: 1356304276, social: '555-55-5555',}"
        ciphertext = self.encrypt(plaintext.encode())
        return ciphertext, self.public_exponent, self.composite


def main():
    mask = 2
    oracle = Oracle()
    ciphertext, public_exponent, composite = oracle.encrypted()
    ciphertext = int.from_bytes(ciphertext, 'big')
    # Because ciphertext = pow(plaintext, public_exponent, composite).
    query = (pow(mask, public_exponent, composite) * ciphertext) % composite
    query = long_to_bytes(query)
    response = oracle.decrypt(query)
    response = int.from_bytes(response, 'big')
    plaintext = (response // mask) % composite
    plaintext = long_to_bytes(plaintext)
    print(plaintext.decode())


if __name__ == '__main__':
    main()
