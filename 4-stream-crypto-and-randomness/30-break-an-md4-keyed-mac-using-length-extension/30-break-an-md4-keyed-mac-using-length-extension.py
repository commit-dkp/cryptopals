# CryptoPals Python Solutions / Set 4 / Solution 30
# Challenge in 30-break-an-md4-keyed-mac-using-length-extension.md .
#
# MD4 was influential in its design, but today, you can find collisions in it with less than 2 hash operations. More at
# https://www.iacr.org/archive/fse2007/45930331/45930331.pdf .
from Crypto.Hash import MD4
from pwnlib.util.fiddling import bits, unbits
from pwnlib.util.lists import group
from secrets import compare_digest, token_bytes


# Pycryptodome's MD4 implementation doesn't let you initialize its state, so here's my own, written as faithfully as I
# could in structure to the standard specification, and validated against the standard test vectors. That said, no one
# should be using MD4 anymore, and you definitely shouldn't be using it this implementation.
class PureMD4:
    @staticmethod
    def _f_conditional(x, y, z):
        # If X then Y else Z.
        return (x & y) | (~x & z)

    @staticmethod
    def _g_majority(x, y, z):
        # If at least two of X, Y, Z are on, then G has a "1" bit in that bit position, else G has a "0" bit.
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _h_parity(x, y, z):
        # Properties similar to those of F and G.
        return x ^ y ^ z

    # The rotate-left (circular left shift) operation, where x is a w-bit word and n is an integer with 0 <= n < w, is
    # defined by ROTL_n(x)=(x << n) ∨ (x >> w - n).
    @staticmethod
    def _rotl(x, w, n):
        return (x << n) | (x >> (w - n))

    def __init__(self):
        self.WORD_BITS = 32
        self.ADD_MOD = 2 ** self.WORD_BITS
        self.message = b''
        self.message_len = 0
        # A four-word buffer (A,B,C,D) is used to compute the message digest. Here each of A, B, C, D is a 32-bit
        # register. These registers are initialized to the following values in hexadecimal, low-order bytes first):
        self.a = 0x67452301
        self.b = 0xefcdab89
        self.c = 0x98badcfe
        self.d = 0x10325476

    # Restore state from a known digest and a guessed message length.
    def init(self, a, b, c, d, message_len):
        self.a = int.from_bytes(a, 'little')
        self.b = int.from_bytes(b, 'little')
        self.c = int.from_bytes(c, 'little')
        self.d = int.from_bytes(d, 'little')
        self.message_len = message_len

    def update(self, message):
        self.message = self.message + message
        self.message_len = self.message_len + len(message)

    # The purpose of this padding is to ensure that the padded message is a multiple of 512 bits. Padding can be
    # inserted before hash computation begins on a message, or at any other time during the hash computation prior to
    # processing the block(s) that will contain the padding.
    def _pad(self):
        # https://www.rfc-editor.org/rfc/rfc1320.txt uses bits, not bytes.
        message = bits(self.message)
        message_len = self.message_len * 8
        message.extend([1])
        zero_bits = -(message_len + 1 + 64) % 512
        message.extend([0] * zero_bits)
        # Message length as a 64-bit bytes object.
        message_len = message_len.to_bytes(8, 'little')
        message_len = bits(message_len)
        message.extend(message_len)
        return unbits(message)

    @staticmethod
    def _parse(padded):
        words = []
        for word in group(4, padded):
            # Word as a 32-bit integer.
            word = int.from_bytes(word, 'little')
            words.append(word)
        return group(16, words)

    # Per https://link.springer.com/content/pdf/10.1007/3-540-38424-3_22.pdf
    def _hash(self):
        padded = self._pad()
        parsed = self._parse(padded)
        for i in range(len(parsed)):
            words = []
            for t in range(len(parsed[i])):
                words.append(parsed[i][t])
            aa = self.a
            bb = self.b
            cc = self.c
            dd = self.d
            self.a = self._rotl((self.a + self._f_conditional(self.b, self.c, self.d) + words[0]) % self.ADD_MOD,
                                self.WORD_BITS, 3)
            self.d = self._rotl((self.d + self._f_conditional(self.a, self.b, self.c) + words[1]) % self.ADD_MOD,
                                self.WORD_BITS, 7)
            self.c = self._rotl((self.c + self._f_conditional(self.d, self.a, self.b) + words[2]) % self.ADD_MOD,
                                self.WORD_BITS, 11)
            self.b = self._rotl((self.b + self._f_conditional(self.c, self.d, self.a) + words[3]) % self.ADD_MOD,
                                self.WORD_BITS, 19)
            self.a = self._rotl((self.a + self._f_conditional(self.b, self.c, self.d) + words[4]) % self.ADD_MOD,
                                self.WORD_BITS, 3)
            self.d = self._rotl((self.d + self._f_conditional(self.a, self.b, self.c) + words[5]) % self.ADD_MOD,
                                self.WORD_BITS, 7)
            self.c = self._rotl((self.c + self._f_conditional(self.d, self.a, self.b) + words[6]) % self.ADD_MOD,
                                self.WORD_BITS, 11)
            self.b = self._rotl((self.b + self._f_conditional(self.c, self.d, self.a) + words[7]) % self.ADD_MOD,
                                self.WORD_BITS, 19)
            self.a = self._rotl((self.a + self._f_conditional(self.b, self.c, self.d) + words[8]) % self.ADD_MOD,
                                self.WORD_BITS, 3)
            self.d = self._rotl((self.d + self._f_conditional(self.a, self.b, self.c) + words[9]) % self.ADD_MOD,
                                self.WORD_BITS, 7)
            self.c = self._rotl((self.c + self._f_conditional(self.d, self.a, self.b) + words[10]) % self.ADD_MOD,
                                self.WORD_BITS, 11)
            self.b = self._rotl((self.b + self._f_conditional(self.c, self.d, self.a) + words[11]) % self.ADD_MOD,
                                self.WORD_BITS, 19)
            self.a = self._rotl((self.a + self._f_conditional(self.b, self.c, self.d) + words[12]) % self.ADD_MOD,
                                self.WORD_BITS, 3)
            self.d = self._rotl((self.d + self._f_conditional(self.a, self.b, self.c) + words[13]) % self.ADD_MOD,
                                self.WORD_BITS, 7)
            self.c = self._rotl((self.c + self._f_conditional(self.d, self.a, self.b) + words[14]) % self.ADD_MOD,
                                self.WORD_BITS, 11)
            self.b = self._rotl((self.b + self._f_conditional(self.c, self.d, self.a) + words[15]) % self.ADD_MOD,
                                self.WORD_BITS, 19)
            # Round 2.
            self.a = self._rotl(
                (self.a + self._g_majority(self.b, self.c, self.d) + words[0] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 3)
            self.d = self._rotl(
                (self.d + self._g_majority(self.a, self.b, self.c) + words[4] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 5)
            self.c = self._rotl(
                (self.c + self._g_majority(self.d, self.a, self.b) + words[8] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 9)
            self.b = self._rotl(
                (self.b + self._g_majority(self.c, self.d, self.a) + words[12] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 13)
            self.a = self._rotl(
                (self.a + self._g_majority(self.b, self.c, self.d) + words[1] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 3)
            self.d = self._rotl(
                (self.d + self._g_majority(self.a, self.b, self.c) + words[5] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 5)
            self.c = self._rotl(
                (self.c + self._g_majority(self.d, self.a, self.b) + words[9] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 9)
            self.b = self._rotl(
                (self.b + self._g_majority(self.c, self.d, self.a) + words[13] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 13)
            self.a = self._rotl(
                (self.a + self._g_majority(self.b, self.c, self.d) + words[2] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 3)
            self.d = self._rotl(
                (self.d + self._g_majority(self.a, self.b, self.c) + words[6] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 5)
            self.c = self._rotl(
                (self.c + self._g_majority(self.d, self.a, self.b) + words[10] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 9)
            self.b = self._rotl(
                (self.b + self._g_majority(self.c, self.d, self.a) + words[14] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 13)
            self.a = self._rotl(
                (self.a + self._g_majority(self.b, self.c, self.d) + words[3] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 3)
            self.d = self._rotl(
                (self.d + self._g_majority(self.a, self.b, self.c) + words[7] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 5)
            self.c = self._rotl(
                (self.c + self._g_majority(self.d, self.a, self.b) + words[11] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 9)
            self.b = self._rotl(
                (self.b + self._g_majority(self.c, self.d, self.a) + words[15] + 0x5a827999) % self.ADD_MOD,
                self.WORD_BITS, 13)
            # Round 3.
            self.a = self._rotl(
                (self.a + self._h_parity(self.b, self.c, self.d) + words[0] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 3)
            self.d = self._rotl(
                (self.d + self._h_parity(self.a, self.b, self.c) + words[8] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 9)
            self.c = self._rotl(
                (self.c + self._h_parity(self.d, self.a, self.b) + words[4] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 11)
            self.b = self._rotl(
                (self.b + self._h_parity(self.c, self.d, self.a) + words[12] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 15)
            self.a = self._rotl(
                (self.a + self._h_parity(self.b, self.c, self.d) + words[2] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 3)
            self.d = self._rotl(
                (self.d + self._h_parity(self.a, self.b, self.c) + words[10] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 9)
            self.c = self._rotl(
                (self.c + self._h_parity(self.d, self.a, self.b) + words[6] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 11)
            self.b = self._rotl(
                (self.b + self._h_parity(self.c, self.d, self.a) + words[14] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 15)
            self.a = self._rotl(
                (self.a + self._h_parity(self.b, self.c, self.d) + words[1] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 3)
            self.d = self._rotl(
                (self.d + self._h_parity(self.a, self.b, self.c) + words[9] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 9)
            self.c = self._rotl(
                (self.c + self._h_parity(self.d, self.a, self.b) + words[5] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 11)
            self.b = self._rotl(
                (self.b + self._h_parity(self.c, self.d, self.a) + words[13] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 15)
            self.a = self._rotl(
                (self.a + self._h_parity(self.b, self.c, self.d) + words[3] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 3)
            self.d = self._rotl(
                (self.d + self._h_parity(self.a, self.b, self.c) + words[11] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 9)
            self.c = self._rotl(
                (self.c + self._h_parity(self.d, self.a, self.b) + words[7] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 11)
            self.b = self._rotl(
                (self.b + self._h_parity(self.c, self.d, self.a) + words[15] + 0x6ed9eba1) % self.ADD_MOD,
                self.WORD_BITS, 15)
            self.a = (self.a + aa) % self.ADD_MOD
            self.b = (self.b + bb) % self.ADD_MOD
            self.c = (self.c + cc) % self.ADD_MOD
            self.d = (self.d + dd) % self.ADD_MOD

    def digest(self):
        self._hash()
        digest = self.a.to_bytes(4, 'little')
        digest = digest + self.b.to_bytes(4, 'little')
        digest = digest + self.c.to_bytes(4, 'little')
        digest = digest + self.d.to_bytes(4, 'little')
        return digest


class Oracle:
    key = token_bytes(MD4.block_size)

    def mac(self, message):
        # Let's keep using Pycryptodome's MD4 for the oracle.
        md4 = MD4.new()
        md4.update(self.key)
        md4.update(message)
        return md4.digest()

    def verify(self, message, mac):
        # Let's keep using Pycryptodome's MD4 for the oracle.
        md4 = MD4.new()
        md4.update(self.key)
        md4.update(message)
        return compare_digest(mac, md4.digest())


def md4_pad(message):
    # https://www.rfc-editor.org/rfc/rfc1320.txt uses bits, not bytes.
    message = bits(message)
    message_len = len(message)
    message.extend([1])
    zero_bits = -(message_len + 1 + 64) % 512
    message.extend([0] * zero_bits)
    # Message length as a 64-bit bytes object.
    message_len = message_len.to_bytes(8, 'little')
    message_len = bits(message_len)
    message.extend(message_len)
    return unbits(message)


def main():
    message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    extension = ';admin=true'
    pure_md4 = PureMD4()
    oracle = Oracle()
    mac = oracle.mac(message.encode())
    width = 4
    hash_words = group(width, mac)
    a = hash_words[0]
    b = hash_words[1]
    c = hash_words[2]
    d = hash_words[3]
    # We don't know the size of the key, but in a proper HMAC, there's no reason for it to exceed the block size.
    for key_len in range(MD4.block_size, -1, -1):
        key = b'\x00' * key_len
        candidate = md4_pad(key + message.encode())
        glue = candidate[key_len + len(message):]
        candidate_len = len(candidate)
        pure_md4.init(a, b, c, d, candidate_len)
        pure_md4.update(extension.encode())
        forged_digest = pure_md4.digest()
        if oracle.verify(message.encode() + glue + extension.encode(), forged_digest):
            print('Length extended!')
            break


if __name__ == '__main__':
    main()
