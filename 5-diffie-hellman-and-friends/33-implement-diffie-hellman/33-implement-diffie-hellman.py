# CryptoPals Python Solutions / Set 5 / Solution 33
# Challenge in 33-implement-diffie-hellman.md .
#
# In 2019, the International Association for Cryptologic Research (IACR) started awarding papers that had stood the
# "test of time", papers that had made a lasting impact on the field and were published exactly 15 years prior. You can
# read them all at https://www.iacr.org/testoftime/ , but perhaps no paper has had such a lasting and immense impact as
# "New Directions In Cryptography" (at https://www-ee.stanford.edu/~hellman/publications/24.pdf ) published in 1976 by
# Whitfield Diffie and Martin Hellman.
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes
from secrets import choice, randbits


class DH:
    def __init__(self, base, modulus, shared_value=None):
        self.base = base
        self.modulus = modulus
        self.private_value = randbits(1024) % self.modulus
        self.public_value = pow(base, self.private_value, self.modulus)
        if shared_value is None:
            self.shared_secret = None
            self.key = None
        else:
            self.set_secret(shared_value)

    def set_secret(self, shared_value):
        # The shared secret is a random group element, but it is not a uniformly random byte object; some of its bytes
        # may be more likely than others. CryptoPal's guidance to "just hash it" rests on the special assumption that a
        # cryptographic hash can extract pseudorandom bits from the shared secret. In "Cryptographic Extraction And Key
        # Derivation: The HKDF Scheme" at https://eprint.iacr.org/2010/264.pdf, the author suggests this could never be
        # sufficiently proven and designs a key derivation function based on HMACs with formal proofs of its security.
        self.shared_secret = pow(shared_value, self.private_value, self.modulus)
        self.shared_secret = long_to_bytes(self.shared_secret)
        # For domain separation, not randomness, per https://soatok.blog/2021/11/17/understanding-hkdf/ .
        salt = 'HMAC Key'
        self.key = HKDF(self.shared_secret, SHA256.block_size, salt.encode(), SHA256)

    def mac(self):
        with open('/usr/share/dict/words', 'r') as words:
            words_split = words.read().split()
        message = choice(words_split)
        hmac_sha256 = HMAC.new(self.key, digestmod=SHA256)
        hmac_sha256.update(message.encode())
        return message.encode() + hmac_sha256.digest()

    def verify(self, message):
        hmac_sha256 = HMAC.new(self.key, digestmod=SHA256)
        hmac_sha256.update(message[:-SHA256.digest_size])
        return hmac_sha256.verify(message[-SHA256.digest_size:])


def main():
    base = 5
    modulus = 37
    alice = DH(base, modulus)
    bob = DH(alice.base, alice.modulus, alice.public_value)
    alice.set_secret(bob.public_value)
    try:
        bob.verify(alice.mac())
    except ValueError:
        print('No shared secret established?!')
    else:
        print('Shared secret established!')
    base = 2
    # If shared_secret = (shared_value ** private_value) % modulus, this would take forever!
    modulus = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
                  'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
                  '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
                  '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
                  '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
                  'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
                  'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
                  'fffffffffffff', 16)
    alice = DH(base, modulus)
    bob = DH(alice.base, alice.modulus, alice.public_value)
    alice.set_secret(bob.public_value)
    try:
        bob.verify(alice.mac())
    except ValueError:
        print('No shared secret established again?!')
    else:
        print('Shared secret established, again!')


if __name__ == '__main__':
    main()
