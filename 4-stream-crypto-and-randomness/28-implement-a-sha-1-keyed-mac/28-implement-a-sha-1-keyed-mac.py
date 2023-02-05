# CryptoPals Python Solutions / Set 4 / Solution 28
# Challenge in 28-implement-a-sha-1-keyed-mac.md .
#
# This isn't really a MAC, because as later challenges will show, it is vulnerable to a length extension attack. Trying
# to avoid this attack by processing the message before the key opens it up to preimage attacks on the message. If you
# can find another meaningful message that has a hash collision with the message used in a MAC, then you now also have a
# collision in the MAC. Trying even harder by processing the key, the message, and then the key again might be better,
# but there's no reason to settle for less than a construction proven to be as secure as the hash function it uses.
# About which I will write more in the next challenge.
from Crypto.Hash import SHA1
from secrets import compare_digest, token_bytes


class Oracle:
    key = token_bytes(SHA1.block_size)

    def mac(self, message):
        sha1 = SHA1.new()
        sha1.update(self.key)
        sha1.update(message)
        return sha1.digest()

    def verify(self, message, mac):
        sha1 = SHA1.new()
        sha1.update(self.key)
        sha1.update(message)
        macd = sha1.digest()
        # Python is full of side-channels, but compare_digest() at least _tries_ to run in constant time. More at
        # https://securitypitfalls.wordpress.com/2018/08/03/constant-time-compare-in-python/
        return compare_digest(mac, macd)


def main():
    oracle = Oracle()
    message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    mac = oracle.mac(message.encode())
    # Verify that you cannot tamper with the message without breaking the "MAC".
    forgery = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true'
    if not oracle.verify(forgery.encode(), mac):
        print('Tampered message, broken "MAC".')
    # Verify that you can't produce a new "MAC" without knowing the secret key.
    sha1 = SHA1.new()
    key = token_bytes(SHA1.block_size)
    sha1.update(key)
    sha1.update(message.encode())
    forgery = sha1.digest()
    if not oracle.verify(message.encode(), forgery):
        print('Wrong key, broken "MAC".')


if __name__ == '__main__':
    main()
