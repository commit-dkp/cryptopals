# CryptoPals Python Solutions / Set 5 / Solution 40
# Challenge in 40-implement-an-e-equals-3-rsa-broadcast-attack.md .
#
# In "Solving Simultaneous Modular Equations Of Low Degree" at https://www.csc.kth.se/~johanh/rsalowexponent.pdf , Johan
# Håstad demonstrated how, without proper padding, the ciphertexts and composites from encrypting the same plaintext
# three times could be used to recover the plaintext. This "broadcast" attack is also an instance of the class of
# attacks described by the Coppersmith method in "Finding A Small Root Of A Univariate Modular Equation" at
# https://link.springer.com/content/pdf/10.1007/3-540-68339-9_14.pdf
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


def oracle():
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    plaintext = choice(words_split)
    ciphertexts = []
    composites = []
    for index in range(3):
        tb_rsa = TextbookRSA()
        ciphertext = tb_rsa.encrypt(plaintext.encode())
        ciphertexts.append(ciphertext)
        composites.append(tb_rsa.composite)
    return ciphertexts, composites


def main():
    ciphertexts, composites = oracle()
    ciphertexts_int = []
    for ciphertext in ciphertexts:
        ciphertext_int = int.from_bytes(ciphertext, 'big')
        ciphertexts_int.append(ciphertext_int)
    # Chinese Remainder Theorem is unnecessary when pow(plaintext, public_exponent) is less than the composite.
    mod_0 = composites[1] * composites[2]
    inv_0 = pow(mod_0, -1, composites[0])
    mod_1 = composites[0] * composites[2]
    inv_1 = pow(mod_1, -1, composites[1])
    mod_2 = composites[0] * composites[1]
    inv_2 = pow(mod_2, -1, composites[2])
    temp_0 = ciphertexts_int[0] * mod_0 * inv_0
    temp_1 = ciphertexts_int[1] * mod_1 * inv_1
    temp_2 = ciphertexts_int[2] * mod_2 * inv_2
    remainder = (temp_0 + temp_1 + temp_2) % (composites[0] * composites[1] * composites[2])
    # Find the cube root.
    low = 0
    high = 1 << ((remainder.bit_length() + 2) // 3)
    while low < high:
        middle = (low + high) // 2
        if pow(middle, 3) < remainder:
            low = middle + 1
        else:
            high = middle
    cube_root = low
    plaintext = long_to_bytes(cube_root)
    print(f'{plaintext.decode()}!')


if __name__ == '__main__':
    main()
