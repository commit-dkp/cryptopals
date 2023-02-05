# CryptoPals Python Solutions / Set 4 / Solution 25
# Challenge in 25-break-random-access-read-write-aes-ctr.md .
#
# This solution to this challenge is hinted at in how the small-key oracle worked in the previous challenge, where it
# encrypted null-bytes with the keystream to output a password-reset token.  Here, the processes is in part reversed,
# whereby asking the oracle to edit the ciphertext with an equal number of null-bytes, its output is the keystream it
# used to encrypt the provided ciphertext and which you can now decrypt yourself. Even if it checked for being asked to
# encrypt null-bytes, you could ask the oracle to edit the old ciphertext with any known plaintext and XOR the new
# ciphertext against your known plaintext to obtain the keystream.
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pwnlib.util.fiddling import xor
from secrets import token_bytes


class Oracle:
    key = token_bytes(AES.block_size)

    def encrypt(self):
        aes_ctr = AES.new(self.key, AES.MODE_CTR)
        # Copy-paste from Challenge 7.
        key = 'YELLOW SUBMARINE'
        aes_ecb = AES.new(key.encode(), AES.MODE_ECB)
        with open('25.txt', 'r') as file:
            ciphertext = b64decode(file.read())
        plaintext = aes_ecb.decrypt(ciphertext)
        plaintext = unpad(plaintext, AES.block_size)
        # Re-encrypt with AES in CTR mode.
        return aes_ctr.nonce, aes_ctr.encrypt(plaintext)

    def edit(self, nonce, ciphertext, offset, plaintext):
        # Jump to the offset's keystream block.
        aes_ctr = AES.new(self.key, AES.MODE_CTR, nonce=nonce, initial_value=offset // AES.block_size)
        prefix = ciphertext[:offset]
        suffix = ciphertext[offset + len(plaintext):]
        # Align the plaintext with the offset's keystream byte within the block.
        pad = b'\x00' * (offset % AES.block_size)
        plaintext = pad + plaintext
        ciphertext = aes_ctr.encrypt(plaintext)
        # Discard the keystream alignment pad.
        ciphertext = ciphertext[len(pad):]
        ciphertext = prefix + ciphertext + suffix
        return aes_ctr.nonce, ciphertext


def main():
    oracle = Oracle()
    nonce, ciphertext = oracle.encrypt()
    # Ask the oracle to encrypt an equal number of null bytes, returning the keystream used to encrypt the ciphertext.
    plaintext = b'\x00' * len(ciphertext)
    nonce, keystream = oracle.edit(nonce, ciphertext, 0, plaintext)
    plaintext = xor(keystream, ciphertext)
    filename = '25-plaintext.txt'
    with open(f'{filename}', 'wb') as file:
        file.write(plaintext)
    print(f'Wrote {filename}!')


if __name__ == '__main__':
    main()
