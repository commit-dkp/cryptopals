# CryptoPals Python Solutions / Set 5 / Solution 35
# Challenge in 35-implement-dh-with-negotiated-groups-and-break-with-malicious-g-parameters.md .
#
# Diffie-Hellman key exchange is secure if the adversary is only passive, but without additional steps to prevent it, an
# active adversary can also influence the parameters used to establish the shared secret and predict its value. While
# not demonstrated here, this can also be done such that neither counter-party detects any errors.
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad, unpad
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
        salt = 'Encryption+Decryption Key'
        self.key = HKDF(self.shared_secret, AES.block_size, salt.encode(), SHA1)

    def encrypt(self, plaintext):
        aes_cbc = AES.new(self.key, AES.MODE_CBC)
        plaintext = pad(plaintext, AES.block_size)
        return aes_cbc.iv + aes_cbc.encrypt(plaintext)

    def decrypt(self, ciphertext):
        aes_cbc = AES.new(self.key, AES.MODE_CBC, iv=ciphertext[:AES.block_size])
        plaintext = aes_cbc.decrypt(ciphertext[AES.block_size:])
        return unpad(plaintext, AES.block_size)


def main():
    base = 2
    modulus = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
                  'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
                  '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
                  '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
                  '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
                  'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
                  'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
                  'fffffffffffff', 16)
    #############
    # Base == 1 #
    #############
    alice = DH(base, modulus)
    # Bob calculates his public_value = pow(1, private_value, modulus) which equals 1.
    bob = DH(1, modulus, alice.public_value)
    # Alice calculates her shared_secret = pow(1, private_value, modulus) which equals 1.
    alice.set_secret(bob.public_value)
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    alices_msg = choice(words_split)
    bob.alices_msg = alice.encrypt(alices_msg.encode())
    # Bob cannot decrypt Alice's message because they do not share the same secret, but Mallory can!
    mallory = DH(base, modulus, 1)
    plaintext = mallory.decrypt(bob.alices_msg)
    print(f'Mallory decrypted "{plaintext.decode()}"!')
    ###################
    # Base == modulus #
    ###################
    alice = DH(base, modulus)
    # Bob calculates his public_value = pow(modulus, private_value, modulus) which equals 0.
    bob = DH(modulus, modulus, alice.public_value)
    # Alice calculates her shared_secret = pow(0 private_value, modulus) which equals 0.
    alice.set_secret(bob.public_value)
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    alices_msg = choice(words_split)
    bob.alices_msg = alice.encrypt(alices_msg.encode())
    # Bob cannot decrypt Alice's message because they do not share the same secret, but Mallory can!
    mallory = DH(base, modulus, 0)
    plaintext = mallory.decrypt(bob.alices_msg)
    print(f'Mallory decrypted "{plaintext.decode()}"!')
    #######################
    # Base == modulus - 1 #
    #######################
    alice = DH(base, modulus)
    # Bob calculates his public_value = pow(modulus - 1, private_value, modulus) which equals 1 if private_value is even
    # and modulus -1 if private_value is odd.
    bob = DH(modulus - 1, modulus, alice.public_value)
    # Alice calculates her shared_secret = pow([1, modulus - 1], private_value, modulus) which equals 1 if private_value
    # is even and modulus - 1 if private_value is odd.
    alice.set_secret(bob.public_value)
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    alices_msg = choice(words_split)
    bob.alices_msg = alice.encrypt(alices_msg.encode())
    # Bob cannot decrypt Alice's message because they do not share the same secret, but Mallory can!
    mallory = DH(base, modulus, modulus - 1)
    try:
        plaintext = mallory.decrypt(bob.alices_msg)
    except ValueError:
        mallory.private_value = mallory.private_value + 1
        mallory.set_secret(modulus - 1)
        plaintext = mallory.decrypt(bob.alices_msg)
    print(f'Mallory decrypted "{plaintext.decode()}"!')


if __name__ == '__main__':
    main()
