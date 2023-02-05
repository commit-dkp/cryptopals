# CryptoPals Python Solutions / Set 6 / Solution 42
# Challenge in 42-bleichenbachers-e-equals-3-rsa-attack.md .
#
# There are a lot of ways the implementation of the RSASSA-PKCS1-v1_5 signature scheme can fail. One of them is when
# the verification function fails to check that the signed hash is aligned at the end of the message. When it doesn't,
# it becomes possible to forge a signature using any public key, with a small exponent, by submitting the e-th root of
# the padded-message-as-integer we would like to be verified. This was originally reported second-hand by Hal Finney at
# https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html , but Filippo Valsorda has a more accessible
# write-up of a variant of this vulnerability he found in the python-rsa package at
# https://words.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/ .
from Crypto.Hash import MD5
from Crypto.Util.number import getStrongPrime, long_to_bytes
from re import compile, DOTALL
from secrets import choice, compare_digest

# DigestInfo BER encoding for MD5 OID from PKCS #1 v1.5 at https://datatracker.ietf.org/doc/html/rfc2313 .
# "30 20" == sequence of 32 bytes
# "30 0c" == sequence of 12 bytes (2 bytes)
# "06082a864886f70d0205" == MD5 OID 1.2.840.113549.2.5 (10 bytes)
# "05 00" == null (2 bytes)
# "04 10" == octet string of 16 bytes (2 bytes)
# 16 bytes spent, 16 bytes remain for MD5 hash.
# Read https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/ for background.
ASN1 = '3020300c06082a864886f70d020505000410'
ASN1 = bytes.fromhex(ASN1)


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
    def sign(self):
        with open('/usr/share/dict/words', 'r') as words:
            words_split = words.read().split()
        word = choice(words_split)
        digest = MD5.new(word.encode()).digest()
        padding_len = self.composite_len - len(digest) - len(ASN1) - 4
        signature = b'\x00\x01\xff' + (b'\xff' * padding_len) + b'\x00' + ASN1 + digest
        return self.decrypt(signature)

    def verify(self, message, signature):
        signature = self.encrypt(signature)
        regex = compile(b'\x00\x01\xff+?\x00(.{18})(.{16})', DOTALL)
        matches = regex.match(signature)
        if not matches:
            return False
        if matches.group(1) != ASN1:
            return False
        signed_hash = matches.group(2)
        message_hash = MD5.new(message).digest()
        return compare_digest(signed_hash, message_hash)


def main():
    oracle = Oracle()
    signature = oracle.sign()
    message = 'hi mom!'
    digest = MD5.new(message.encode()).digest()
    padding_len = len(signature) - len(digest) - len(ASN1) - 4
    forgery = b'\x00\x01\xff\x00' + ASN1 + digest + (b'\x00' * padding_len)
    forgery = int.from_bytes(forgery, 'big')
    # Find the cube root.
    low = 0
    high = 1 << ((forgery.bit_length() + 2) // 3)
    while low < high:
        middle = (low + high) // 2
        if pow(middle, 3) < forgery:
            low = middle + 1
        else:
            high = middle
    cube_root = low
    forgery = long_to_bytes(cube_root)
    if oracle.verify(message.encode(), forgery):
        print('Verified!')
    else:
        print('Not Verified?!')


if __name__ == '__main__':
    main()
