# CryptoPals Python Solutions / Set 5 / Solution 34
# Challenge in 34-implement-a-mitm-key-fixing-attack-on-diffie-hellman-with-parameter-injection.md .
#
# Diffie-Hellman key exchange is secure if the adversary is only passive, but without additional steps to prevent it, an
# active adversary can perform the key exchange with both counter-parties and decrypt (or modify then re-encrypt) the
# traffic between them.
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
    alice = DH(base, modulus)
    # Mallory intercepts the modulus and base Alice has chosen.
    mallory = DH(alice.base, alice.modulus)
    # Mallory injects their parameters into Bob's exchange.
    bob = DH(mallory.base, mallory.modulus, mallory.modulus)
    # Mallory injects their parameters into Alice's exchange.
    alice.set_secret(mallory.modulus)
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    message = choice(words_split)
    # Mallory stores a copy of Alice's encrypted message to Bob.
    mallory.alices_msg = alice.encrypt(message.encode())
    # Mallory forwards Alice's encrypted message to Bob.
    bob.alices_msg = mallory.alices_msg
    plaintext = bob.decrypt(bob.alices_msg)
    # Mallory stores a copy of Bob's encrypted message to Alice.
    mallory.bobs_msg = bob.encrypt(plaintext)
    # Mallory forwards Bob's encrypted message to Alice.
    alice.bobs_msg = mallory.bobs_msg
    # Mallory calculates the shared secret they forced Alice and Bob to use.
    mallory.set_secret(mallory.modulus)
    print(f'Mallory decrypted "{mallory.decrypt(mallory.alices_msg).decode()}" and '
          f'"{mallory.decrypt(mallory.bobs_msg).decode()}"!')


if __name__ == '__main__':
    main()
