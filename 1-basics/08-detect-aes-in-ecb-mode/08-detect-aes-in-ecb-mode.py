# CryptoPals Python Solutions / Set 1 / Solution 8
# Challenge in 08-detect-aes-in-ecb-mode.md .
#
# Since the same 16 byte plaintext block will always produce the same 16 byte ciphertext ECB block, all you need to do
# is check which ciphertext has a repeated block. However, block sizes are not defined by the block mode but by the
# block cipher. So, if you assumed a block size of 16 bytes but the plaintexts had been encrypted with the Blowfish
# cipher instead of AES, then your detection code would fail because Blowfish uses an 8-byte block.
from pwnlib.util.lists import group


def main():
    # At 512 bytes, http://www.ciphergoth.org/crypto/mercy/ is the largest block cipher I know.
    block_size_max = 512
    ciphertexts = []
    with open('8.txt', 'r') as file:
        for ciphertext in file:
            ciphertext = bytes.fromhex(ciphertext)
            ciphertexts.append(ciphertext)
    # https://iacr.org/archive/fse2007/45930457/45930457.pdf says 1-byte block ciphers could exist, but then they
    # couldn't be distinguished from stream ciphers.
    for block_size in range(block_size_max, 1, -1):
        for ciphertext in ciphertexts:
            blocks = group(block_size, ciphertext)
            block_len = len(blocks)
            for index in range(block_len - 1):
                if blocks[index] in blocks[index + 1:]:
                    print(f'ECB: {blocks[index].hex()} repeats in {ciphertext.hex()}!')
                    return
    print('No repeating block?!')


if __name__ == '__main__':
    main()
