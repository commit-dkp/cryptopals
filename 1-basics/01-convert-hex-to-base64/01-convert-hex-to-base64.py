# CryptoPals Python Solutions / Set 1 / Solution 1
# Challenge in 01-convert-hex-to-base64.md .
#
# A demonstration of how to convert from hex to base64 with Python. If you'd like an extra challenge, go ahead and write
# your own hex-to-bytes and bytes-to-base64 conversion code, but it won't be necessary to reuse your code for the rest
# of the exercises.
from base64 import b64encode


def main():
    # "I'm killing your brain like a poisonous mushroom".encode().hex()
    hexed = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    byted = bytes.fromhex(hexed)
    based = b64encode(byted)
    print(based.decode())


if __name__ == '__main__':
    main()
