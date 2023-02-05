# CryptoPals Python Solutions / Set 3 / Solution 17
# Challenge in 17-the-cbc-padding-oracle.md .
#
# For every ciphertext block except the last, regard the current block as the IV, the subsequent block as the
# ciphertext, and create a plaintext block of zeros. For every possible padding block and every possible plaintext byte
# guess, XOR the first padding byte with the plaintext byte guess, and then XOR that block with the IV. Query the oracle
# with this forged IV and its ciphertext until the padding is valid, and reuse the plaintext block in subsequent
# forgeries until each of its bytes has been recovered. Then, move on from the next ciphertext block to the
# next-to-last.
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwnlib.util.fiddling import xor
from pwnlib.util.lists import group
from secrets import choice, token_bytes


class Oracle:
    key = token_bytes(AES.block_size)

    def encrypt(self):
        aes_cbc = AES.new(self.key, AES.MODE_CBC)
        # There are some single-byte errors in the original plaintext copied from CryptoPals. It's probably not your
        # mistake if some of your decrypts have a typo.
        strings = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                   'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                   'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
                   'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                   'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                   'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                   'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                   'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                   'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                   'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
        plaintext = choice(strings)
        plaintext = pad(plaintext.encode(), AES.block_size)
        return aes_cbc.iv + aes_cbc.encrypt(plaintext)

    def decrypt(self, ciphertext):
        if len(ciphertext) == 0:
            raise ValueError
        aes_cbc = AES.new(self.key, AES.MODE_CBC, iv=ciphertext[:AES.block_size])
        plaintext = aes_cbc.decrypt(ciphertext[AES.block_size:])
        try:
            # Even if this code were fixed to not throw a padding exception, the unpad function is written to exit early
            # when the padding is invalid, which leaves a side-channel. To plug that leak, we'd need to read all the
            # bytes in the last block, and not return until each padding byte has been checked against the padding
            # length. For more, check out https://www.bearssl.org/constanttime.html#cbc-padding .
            unpad(plaintext, AES.block_size)
        except ValueError:
            return False
        return True


def main():
    # At 512 bytes, http://www.ciphergoth.org/crypto/mercy/ is the largest block cipher I know.
    block_size_max = 512
    query = 'A'
    byte_value_max = 0xff
    oracle = Oracle()
    block_size = 0
    for size in range(2, block_size_max + 1):
        fake_iv = query * size
        fake_ciphertext = query * size
        query_size = bytearray(fake_iv + fake_ciphertext, encoding='utf8')
        # Exploits the padding vulnerability to discover the block size.
        for pad_byte in range(byte_value_max):
            query_size[size - 1] = pad_byte
            try:
                if oracle.decrypt(query_size):
                    block_size = size
                    break
            except ValueError:
                continue
        if block_size:
            break
    if block_size == 0:
        print('Not CBC mode?!')
        return
    # Break it!
    ciphertext = oracle.encrypt()
    blocks = group(block_size, ciphertext)
    blocks_len = len(blocks)
    padded = b''
    for index in range(blocks_len - 1):
        plaintext = bytearray(query * block_size, encoding='utf8')
        iv = blocks[index]
        ciphertext = blocks[index + 1]
        for index_max in range(1, block_size + 1):
            prefix = bytes([0]) * (block_size - index_max)
            suffix = bytes([index_max]) * index_max
            index_neg = block_size - index_max
            padding = prefix + suffix
            for candidate in range(byte_value_max):
                plaintext[index_neg] = candidate
                candidate_xor = xor(plaintext, padding)
                candidate_xor = xor(iv, candidate_xor)
                valid = oracle.decrypt(candidate_xor + ciphertext)
                if valid:
                    # The penultimate byte might be part of the valid padding, e.g. when the guess flips the last byte
                    # to b'\x02' and the penultimate byte is also b'\x02'. The oracle will respond positively, but the
                    # guess is incorrect because it has not flipped the last byte to b'\x01'.
                    if index_neg == block_size - 1:
                        candidate_xor = bytearray(candidate_xor)
                        penultimate = index_neg - 1
                        # Modify the penultimate byte and query the oracle again.
                        candidate_xor[penultimate] = candidate_xor[penultimate] ^ 1
                        if not oracle.decrypt(candidate_xor + ciphertext):
                            # The penultimate byte was part of the valid padding, keep searching!
                            continue
                    break
        padded = padded + plaintext
    based = unpad(padded, block_size)
    debased = b64decode(based)
    print(debased.decode())


if __name__ == '__main__':
    main()
