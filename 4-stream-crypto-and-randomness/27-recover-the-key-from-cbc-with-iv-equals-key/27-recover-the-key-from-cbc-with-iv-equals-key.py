# CryptoPals Python Solutions / Set 4 / Solution 27
# Challenge in 27-recover-the-key-from-cbc-with-iv-equals-key.md .
#
# Key=IV is what happens when folks fail to appreciate the very different roles that different inputs into a
# cryptographic algorithm play. On the other hand, most folks should not have to appreciate the very different roles
# that different inputs into a cryptographic algorithm play, because they have a trustworthy library that encodes that
# appreciation on their behalf and does not easily allow them to "optimize" it in any way.
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwnlib.util.fiddling import xor
from pwnlib.util.lists import group
from secrets import token_bytes
from urllib.parse import parse_qs, quote


class Oracle:
    key = token_bytes(AES.block_size)

    def encrypt(self, userdata):
        if len(userdata) == 0:
            raise ValueError
        aes_cbc = AES.new(self.key, AES.MODE_CBC, iv=self.key)
        kvd = f'comment1=cooking%20MCs;userdata={quote(userdata)};comment2=%20like%20a%20pound%20of%20bacon'
        padded = pad(kvd.encode(), AES.block_size)
        return aes_cbc.encrypt(padded)

    def decrypt(self, ciphertext):
        if len(ciphertext) == 0:
            raise ValueError
        aes_cbc = AES.new(self.key, AES.MODE_CBC, iv=self.key)
        plaintext = aes_cbc.decrypt(ciphertext)
        plaintext = unpad(plaintext, AES.block_size)
        try:
            kvd = parse_qs(plaintext.decode(), strict_parsing=True, separator=';')
        except UnicodeError:
            # Per the challenge instructions, still return plaintext when there is a decoding error.
            return plaintext
        if kvd['admin'][0] == 'true':
            return True
        return False


def main():
    oracle = Oracle()
    query = 'A'
    ciphertext = oracle.encrypt(query.encode())
    initial_len = len(ciphertext)
    current_len = initial_len
    # At 512 bytes, http://www.ciphergoth.org/crypto/mercy/ is the largest block cipher I know.
    block_size_max = 512
    query_size = query
    for _ in range(block_size_max + 1):
        query_size = query_size + query
        ciphertext = oracle.encrypt(query_size.encode())
        current_len = len(ciphertext)
        if current_len != initial_len:
            break
    block_size = current_len - initial_len
    if block_size <= 1:
        print('Probably not a block cipher!')
        return
    # Break it!
    ciphertext = oracle.encrypt(query.encode())
    nulls = b'\x00' * block_size
    plaintext = oracle.decrypt(ciphertext[:block_size] + nulls + ciphertext)
    blocks = group(block_size, plaintext)
    key = xor(blocks[0], blocks[2])
    # As the most widely-deployed 16-byte block cipher, it wouldn't be too wild a guess to try decrypting with AES.
    aes_cbc = AES.new(key, AES.MODE_CBC, iv=key)
    plaintext = aes_cbc.decrypt(ciphertext)
    plaintext = unpad(plaintext, block_size)
    print(plaintext.decode())


if __name__ == '__main__':
    main()
