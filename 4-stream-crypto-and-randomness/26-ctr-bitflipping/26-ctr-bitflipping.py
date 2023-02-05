# CryptoPals Python Solutions / Set 4 / Solution 26
# Challenge in 26-ctr-bitflipping.md .
#
# CTR bit-flipping is even easier than CBC bit-flipping because you can flip any bit at all without corrupting a whole
# block into likely-undecodable garbage, and you can flip as many bits as you want instead of only up to half the blocks
# in the ciphertext.
from Crypto.Cipher import AES
from pwnlib.util.fiddling import xor
from secrets import token_bytes
from urllib.parse import parse_qs, quote


class Oracle:
    key = token_bytes(AES.block_size)

    def encrypt(self, userdata):
        if len(userdata) == 0:
            raise ValueError
        aes_ctr = AES.new(self.key, AES.MODE_CTR)
        kvd = f'comment1=cooking%20MCs;userdata={quote(userdata)};comment2=%20like%20a%20pound%20of%20bacon'
        return aes_ctr.nonce, aes_ctr.encrypt(kvd.encode())

    def decrypt(self, nonce, ciphertext):
        if len(ciphertext) == 0:
            raise ValueError
        aes_ctr = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        plaintext = aes_ctr.decrypt(ciphertext)
        kvd = parse_qs(plaintext.decode(), strict_parsing=True, separator=';')
        if kvd['admin'][0] == 'true':
            return True
        return False


def main():
    oracle = Oracle()
    query = 'A'
    admin = ';admin=true'
    admin_len = len(admin)
    # With CBC bit-flipping, you could only safely modify the first block, but maybe some application-layer validation
    # would complain that "comment1" was missing. With CTR bit-flipping, you can preserve the wrapped bytes and only
    # flip the bytes where your plaintext was inserted to still pass application-layer validation.
    query_admin = query * admin_len
    nonce, ciphertext = oracle.encrypt(query_admin)
    # It's assumed you know what the oracle will wrap your plaintext with before encrypting, otherwise how would you
    # know what would be fun to patch in?
    prepend = 'comment1=cooking%20MCs;userdata='
    prepend_len = len(prepend)
    admin_end = prepend_len + admin_len
    patch = ciphertext[prepend_len:admin_end]
    xord = xor(admin.encode(), query.encode())
    patched = xor(patch, xord)
    admin = oracle.decrypt(nonce, ciphertext[:prepend_len] + patched + ciphertext[admin_end:])
    if admin:
        print('admin=true')
    else:
        print('Not admin=true ?!')


if __name__ == '__main__':
    main()
