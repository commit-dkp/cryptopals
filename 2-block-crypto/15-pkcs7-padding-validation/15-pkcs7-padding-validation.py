# CryptoPals Python Solutions / Set 2 / Solution 15
# Challenge in 15-pkcs7-padding-validation.md .
#
# This just demonstrates how to use the Pycryptodome library's PKCS #7 implementation. If you'd like an extra challenge,
# go ahead and write your own PKCS #7 unpadding code, but it won't be necessary to reuse your code for the rest of the
# exercises.
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def main():
    pads = [b'ICE ICE BABY\x04\x04\x04\x04', b'ICE ICE BABY\x05\x05\x05\x05', b'ICE ICE BABY\x01\x02\x03\x04']
    for pad in pads:
        try:
            unpad(pad, AES.block_size)
            print(f'{pad} - PKCS#7 padding is correct')
        except ValueError as value_error:
            print(f'{pad} - {value_error}')


if __name__ == '__main__':
    main()
