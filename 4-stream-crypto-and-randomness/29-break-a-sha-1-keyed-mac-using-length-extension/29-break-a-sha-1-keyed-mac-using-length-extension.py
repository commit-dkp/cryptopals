# CryptoPals Python Solutions / Set 4 / Solution 29
# Challenge in 29-break-a-sha-1-keyed-mac-using-length-extension.md .
#
# A proper HMAC differs from a what is usually called a "keyed hash" in that is defined as H(key || H(key || message))
# where H is your hash function. Because the outer hash masks the results of the intermediate hash, there are no known
# extension attacks. There are also a couple of padding values used, but the only requirement of them is that they
# differ from in each in at least one bit.
from Crypto.Hash import SHA1
from pwnlib.util.fiddling import bits, unbits
from pwnlib.util.lists import group
from secrets import compare_digest, token_bytes


# Pycryptodome's SHA-1 implementation doesn't let you initialize its state, so here's my own, written as faithfully as I
# could in structure to the standard specification, and validated against the standard test vectors. That said, no one
# should be using SHA-1 anymore, and you definitely shouldn't be using it this implementation.
class PureSHA1:
    # The rotate-left (circular left shift) operation, where x is a w-bit word and n is an integer with 0 <= n < w, is
    # defined by ROTL_n(x)=(x << n) ∨ (x >> w - n).
    def _rotl(self, x, w, n):
        return ((x << n) | (x >> (w - n))) % self.ADD_MOD

    # SHA-1 uses a sequence of logical functions, f_0, f_1, ..., f_79. Each function f_t, where 0 <=t <= 79, operates
    # on three 32-bit words, x, y, and z, and produces a 32-bit word as output.
    @staticmethod
    def _logicals(t, x, y, z):
        if 0 <= t <= 19:
            return (x & y) | ((~x) & z)
        elif 20 <= t <= 39 or 60 <= t <= 79:
            return x ^ y ^ z
        elif 40 <= t <= 59:
            return (x & y) | (x & z) | (y & z)
        elif 60 <= t <= 79:
            return x ^ y ^ z

    # SHA-1 uses a sequence of eighty constant 32-bit words, K_0, K_1, ..., K_79.
    @staticmethod
    def _constants(t):
        if 0 <= t <= 19:
            return 0x5a827999
        elif 20 <= t <= 39:
            return 0x6ed9eba1
        elif 40 <= t <= 59:
            return 0x8f1bbcdc
        elif 60 <= t <= 79:
            return 0xca62c1d6

    def __init__(self):
        self.WORD_BITS = 32
        self.ADD_MOD = 2 ** self.WORD_BITS
        self.message = b''
        self.message_len = 0
        # Before hash computation begins for each of the secure hash algorithms, the initial hash value, H(0), must be
        # set. For SHA-1, the initial hash value, H(0), shall consist of the following five 32-bit words, in hex:
        self.h0 = 0x67452301
        self.h1 = 0xefcdab89
        self.h2 = 0x98badcfe
        self.h3 = 0x10325476
        self.h4 = 0xc3d2e1f0

    # Restore state from a known digest and a guessed message length.
    def init(self, h0, h1, h2, h3, h4, message_len):
        self.h0 = int.from_bytes(h0, 'big')
        self.h1 = int.from_bytes(h1, 'big')
        self.h2 = int.from_bytes(h2, 'big')
        self.h3 = int.from_bytes(h3, 'big')
        self.h4 = int.from_bytes(h4, 'big')
        self.message_len = message_len

    def update(self, message):
        self.message = self.message + message
        self.message_len = self.message_len + len(message)

    # The purpose of this padding is to ensure that the padded message is a multiple of 512 bits. Padding can be
    # inserted before hash computation begins on a message, or at any other time during the hash computation prior to
    # processing the block(s) that will contain the padding.
    def _pad(self):
        # https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf uses bits, not bytes.
        message = bits(self.message)
        message_len = self.message_len * 8
        message.extend([1])
        zero_bits = -(message_len + 1 + 64) % 512
        message.extend([0] * zero_bits)
        # Message length as a 64-bit bytes object.
        message_len = message_len.to_bytes(8, 'big')
        message_len = bits(message_len)
        message.extend(message_len)
        return unbits(message)

    @staticmethod
    def _parse(padded):
        words = []
        for word in group(4, padded):
            # Word as a 32-bit integer.
            word = int.from_bytes(word, 'big')
            words.append(word)
        return group(16, words)

    # Tested against
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
    def _hash(self):
        padded = self._pad()
        parsed = self._parse(padded)
        for i in range(len(parsed)):
            words = []
            for t in range(len(parsed[i])):
                words.append(parsed[i][t])
            for t in range(16, 80):
                word = words[t - 3] ^ words[t - 8] ^ words[t - 14] ^ words[t - 16]
                shifted = self._rotl(word, self.WORD_BITS, 1)
                words.append(shifted)
            a = self.h0
            b = self.h1
            c = self.h2
            d = self.h3
            e = self.h4
            for t in range(80):
                shifted = self._rotl(a, self.WORD_BITS, 5)
                logical = self._logicals(t, b, c, d)
                constant = self._constants(t)
                temp = (shifted + logical + e + constant + words[t]) % self.ADD_MOD
                e = d
                d = c
                c = self._rotl(b, self.WORD_BITS, 30)
                b = a
                a = temp
            self.h0 = (self.h0 + a) % self.ADD_MOD
            self.h1 = (self.h1 + b) % self.ADD_MOD
            self.h2 = (self.h2 + c) % self.ADD_MOD
            self.h3 = (self.h3 + d) % self.ADD_MOD
            self.h4 = (self.h4 + e) % self.ADD_MOD

    def digest(self):
        self._hash()
        digest = self.h0.to_bytes(4, 'big')
        digest = digest + self.h1.to_bytes(4, 'big')
        digest = digest + self.h2.to_bytes(4, 'big')
        digest = digest + self.h3.to_bytes(4, 'big')
        digest = digest + self.h4.to_bytes(4, 'big')
        return digest


class Oracle:
    key = token_bytes(SHA1.block_size)

    def mac(self, message):
        # Let's keep using Pycryptodome's SHA-1 for the oracle.
        sha1 = SHA1.new()
        sha1.update(self.key)
        sha1.update(message)
        return sha1.digest()

    def verify(self, message, mac):
        # Let's keep using Pycryptodome's SHA-1 for the oracle.
        sha1 = SHA1.new()
        sha1.update(self.key)
        sha1.update(message)
        return compare_digest(mac, sha1.digest())


def sha1_pad(message):
    # https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf uses bits, not bytes.
    message = bits(message)
    message_len = len(message)
    message.extend([1])
    zero_bits = -(message_len + 1 + 64) % 512
    message.extend([0] * zero_bits)
    # Message length as a 64-bit bytes object.
    message_len = message_len.to_bytes(8, 'big')
    message_len = bits(message_len)
    message.extend(message_len)
    return unbits(message)


def main():
    message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    extension = ';admin=true'
    pure_sha1 = PureSHA1()
    oracle = Oracle()
    mac = oracle.mac(message.encode())
    width = 4
    hash_words = group(width, mac)
    h0 = hash_words[0]
    h1 = hash_words[1]
    h2 = hash_words[2]
    h3 = hash_words[3]
    h4 = hash_words[4]
    # We don't know the size of the key, but in a proper HMAC, there's no reason for it to exceed the block size.
    for key_len in range(SHA1.block_size, -1, -1):
        key = b'\x00' * key_len
        candidate = sha1_pad(key + message.encode())
        glue = candidate[key_len + len(message):]
        candidate_len = len(candidate)
        pure_sha1.init(h0, h1, h2, h3, h4, candidate_len)
        pure_sha1.update(extension.encode())
        forged_digest = pure_sha1.digest()
        if oracle.verify(message.encode() + glue + extension.encode(), forged_digest):
            print('Length extended!')
            break


if __name__ == '__main__':
    main()
