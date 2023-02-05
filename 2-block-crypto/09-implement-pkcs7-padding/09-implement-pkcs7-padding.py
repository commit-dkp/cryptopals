# CryptoPals Python Solutions / Set 2 / Solution 9
# Challenge in 09-implement-pkcs7-padding.md .
#
# A demonstration of how to use the Pycryptodome library's PKCS #7 implementation. If you'd like an extra challenge, go
# ahead and write your own PKCS #7 padding code, but it won't be necessary to reuse your code for the rest of the
# exercises.
from Crypto.Util.Padding import pad


def main():
    not_padded = 'YELLOW SUBMARINE'
    padded_len = 20
    padded = pad(not_padded.encode(), padded_len)
    print(padded)


if __name__ == '__main__':
    main()
