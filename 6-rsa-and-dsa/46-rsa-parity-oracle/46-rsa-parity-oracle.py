# CryptoPals Python Solutions / Set 6 / Solution 46
# Challenge in 46-rsa-parity-oracle.md .
#
# Since everything in RSA is as-integer, the plaintext-as-integer must be some value between zero and the composite. If
# you have a ciphertext, multiply it by 2, and submit it to a least-significant-bit oracle, you will learn if the
# plaintext-as-integer is between zero and the composite divided by 2. Iterate on this, and eventually you will reach
# the two identical numbers that the plaintext-as-integer is "between", which is the plaintext-as-integer itself.
from base64 import b64decode
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
    def start(self):
        message = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
        message = b64decode(message)
        return self.encrypt(message), self.public_exponent, self.composite

    def parity(self, ciphertext):
        plaintext = self.decrypt(ciphertext)
        plaintext = int.from_bytes(plaintext, 'big')
        if plaintext % 2 == 0:
            return True
        return False


def main():
    oracle = Oracle()
    ciphertext, public_exponent, composite = oracle.start()
    # Rather than halving the interval at each step and descending into the correct one depending on the parity, double
    # the interval and ascend to avoid floating-point numbers.
    doubler = pow(2, public_exponent, composite)
    upper_bound = 1
    lower_bound = 0
    plaintext = b''
    for bit_counter in range(1, composite.bit_length() + 1):
        ciphertext = int.from_bytes(ciphertext, 'big')
        ciphertext = (ciphertext * doubler) % composite
        ciphertext = long_to_bytes(ciphertext)
        width = upper_bound - lower_bound
        upper_bound = upper_bound * 2
        lower_bound = lower_bound * 2
        if oracle.parity(ciphertext):
            upper_bound = upper_bound - width
        else:
            lower_bound = lower_bound + width
        # The upper bound is an index into the modulus search space, which has been divided by 2 ** bit_counter.
        plaintext = (upper_bound * composite) // (2 ** bit_counter)
    plaintext = long_to_bytes(plaintext)
    print(plaintext.decode())


if __name__ == '__main__':
    main()
