# CryptoPals Python Solutions / Set 2 / Solution 16
# Challenge in 16-cbc-bit-flipping-attacks.md .
#
# Why this attack works might be apparent from the demonstration of CBC-decrypt in Challenge 10, where the ciphertext
# being decrypted is XOR'd by the previous block. Therefore, you can modify one or more CBC blocks to make predictable
# changes to the decryption of adjacent blocks, as long as they don't overlap. You can safely modify the IV to patch
# the first block, but modifying any ciphertext block to patch its adjacent block will likely render that modified block
# as undecodable plaintext. In some applications, this matters; in others, it does not!
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwnlib.util.fiddling import xor
from secrets import token_bytes
from urllib.parse import parse_qs, quote


class Oracle:
    key = token_bytes(AES.block_size)

    def encrypt(self, userdata):
        if len(userdata) == 0:
            raise ValueError
        aes_cbc = AES.new(self.key, AES.MODE_CBC)
        kvd = f'comment1=cooking%20MCs;userdata={quote(userdata)};comment2=%20like%20a%20pound%20of%20bacon'
        plaintext = pad(kvd.encode(), AES.block_size)
        return aes_cbc.iv + aes_cbc.encrypt(plaintext)

    def decrypt(self, ciphertext):
        if len(ciphertext) == 0:
            raise ValueError
        aes_cbc = AES.new(self.key, AES.MODE_CBC, iv=ciphertext[:AES.block_size])
        plaintext = aes_cbc.decrypt(ciphertext[AES.block_size:])
        plaintext = unpad(plaintext, AES.block_size)
        kvd = parse_qs(plaintext.decode(), strict_parsing=True, separator=';')
        if kvd['admin'][0] == 'true':
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
    # Define the patch.
    patch = 'admin=true;'
    patch_len = len(patch)
    terminator = 'Z='
    terminator_len = len(terminator)
    # It's assumed you know what the oracle will wrap your plaintext with before encrypting, otherwise how would you
    # know what would be fun to patch in?
    prepend = 'comment1=cooking%20MCs;userdata='
    append = ';comment2=%20like%20a%20pound%20of%20bacon'
    pend_len = len(prepend) + len(query) + len(append)
    if pend_len < block_size:
        # Fill the block with known bytes.
        remainder = block_size - pend_len
        query = query + (query * remainder)
    wrapped = prepend + query + append
    wrapped_len = len(wrapped)
    if patch_len < (terminator_len + wrapped_len):
        # Add a terminating key for strict JSON.
        patch = patch + terminator
    # The patch cannot be larger than the IV, otherwise it will scramble the adjacent ciphertext block.
    if patch_len > block_size:
        print("Patch doesn't fit!")
        return
    patch_block = xor(patch.encode(), wrapped.encode(), cut='min')
    # Query the oracle to obtain the assumed IV.
    query_iv = query
    ciphertext = oracle.encrypt(query_iv)
    iv = ciphertext[:block_size]
    ciphertext = ciphertext[block_size:]
    iv = xor(patch_block, iv)
    query_patched = iv + ciphertext
    if oracle.decrypt(query_patched):
        print('admin=true')
    else:
        print('Not admin=true?!')


if __name__ == '__main__':
    main()
