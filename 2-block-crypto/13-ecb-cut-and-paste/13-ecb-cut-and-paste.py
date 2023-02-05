# CryptoPals Python Solutions / Set 2 / Solution 13
# Challenge in 13-ecb-cut-and-paste.md .
#
# As a natural consequence of ECB blocks being encrypted independently, you can pick and choose ciphertext blocks to be
# decrypted into a desired plaintext. When you can choose the plaintext to be encrypted, even better. The challenge
# description is a little unrealistic, however, as only quoting the "&" and "=" characters would make it easy to submit
# padding bytes to be encrypted. Here, where all reserved characters are quoted, a couple more oracle queries will be
# required.
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwnlib.util.lists import group
from secrets import token_bytes
from urllib.parse import parse_qs, quote


class Oracle:
    key = token_bytes(AES.block_size)

    def encrypt(self, address):
        if len(address) == 0:
            raise ValueError
        aes_ecb = AES.new(self.key, AES.MODE_ECB)
        # b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10' becomes...
        # b'%10%10%10%10%10%10%10%10%10%10%10%10%10%10%10%10' ... so don't waste your time.
        kvd = f'email={quote(address)}&uid=10&role=user'
        plaintext = pad(kvd.encode(), AES.block_size)
        return aes_ecb.encrypt(plaintext)

    def decrypt(self, ciphertext):
        if len(ciphertext) == 0:
            raise ValueError
        aes_ecb = AES.new(self.key, AES.MODE_ECB)
        plaintext = aes_ecb.decrypt(ciphertext)
        plaintext = unpad(plaintext, AES.block_size)
        kvd = parse_qs(plaintext.decode(), strict_parsing=True)
        if kvd['role'][0] == 'admin':
            return True
        return False


def main():
    oracle = Oracle()
    query = 'A'
    ciphertext = oracle.encrypt(query)
    initial_len = len(ciphertext)
    current_len = initial_len
    # At 512 bytes, http://www.ciphergoth.org/crypto/mercy/ is the largest block cipher I know.
    block_size_max = 512
    query_size = query
    for _ in range(block_size_max + 1):
        query_size = query_size + query
        ciphertext = oracle.encrypt(query_size)
        current_len = len(ciphertext)
        if current_len != initial_len:
            break
    block_size = current_len - initial_len
    if block_size <= 1:
        print('Probably not a block cipher!')
        return
    # Accounting for the possibility of a prefix, three blocks would be enough to force one repetition. Since you also
    # need to account for the probability of small-sized blocks repeating randomly, ask for four blocks and look for two
    # repetitions!
    block = query * block_size
    block_count = 4
    query_mode = block * block_count
    ciphertext = oracle.encrypt(query_mode)
    blocks = group(block_size, ciphertext)
    blocks_len = len(blocks)
    try:
        for index in range(blocks_len - 2):
            if blocks[index] == blocks[index + 1] and blocks[index] == blocks[index + 2]:
                raise StopIteration
        print('Not ECB mode?!')
        return
    except StopIteration:
        pass
    # Fill email to a block boundary, for prefix and postfix.
    query_pfix = 'email='
    query_len = len(query_pfix)
    query_rem = block_size - (query_len % block_size)
    pfix_block = oracle.encrypt(query * query_rem)[:query_len + query_rem]
    # Fill email to push '&role=' to the end of a block.
    query_role = 'email=&uid=10&role='
    query_len = len(query_role)
    query_rem = block_size - (query_len % block_size)
    false_start = query_len + query_rem
    role_len = len('&role=')
    role_rem = block_size - (role_len % block_size)
    start = false_start - role_len - role_rem
    role_block = oracle.encrypt(query * query_rem)[start:start + role_len + role_rem]
    # Fill email to push 'admin' to the start of a block.
    query_admin = 'email='
    query_len = len(query_admin)
    query_rem = block_size - (query_len % block_size)
    start = query_len + query_rem
    admin_len = len('admin')
    admin_rem = block_size - (admin_len % block_size)
    admin_block = oracle.encrypt(query.encode() * query_rem + 'admin'.encode())[start:start + admin_len + admin_rem]
    # Fill email to push the whole profile to the end of a block, for padding.
    query_pad = 'email=&uid=10&role=user'
    query_len = len(query_pad)
    query_rem = block_size - (query_len % block_size)
    start = query_len + query_rem
    padding_block = oracle.encrypt(query * query_rem)[start:start + block_size]
    # Paste the blocks together.
    paste = pfix_block + role_block + admin_block + pfix_block + padding_block
    if oracle.decrypt(paste):
        print('role=admin')
    else:
        print('Not role=admin?!')


if __name__ == '__main__':
    main()
