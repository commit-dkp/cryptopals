# CryptoPals Python Solutions / Set 3 / Solution 19
# Challenge in 19-break-fixed-nonce-ctr-mode-using-substitutions.md .
#
# Technically, the oracle gives enough from the number of lines and number of bytes in each line, to find the entire
# plaintext and use it as a crib... if you had a system sophisticated to search on those parameters, but you don't.
# Instead, you're being asked to attack this with "pen & paper" techniques, which worked quite well before automation
# but are suboptimal today.
from base64 import b64decode
from collections import Counter
from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_CTR
from pwnlib.util.fiddling import xor
from secrets import token_bytes


def oracle():
    baseds = ['SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
              'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
              'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
              'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
              'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
              'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
              'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
              'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
              'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
              'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
              'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
              'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
              'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
              'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
              'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
              'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
              'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
              'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
              'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
              'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
              'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
              'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
              'U2hlIHJvZGUgdG8gaGFycmllcnM/',
              'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
              'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
              'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
              'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
              'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
              'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
              'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
              'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
              'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
              'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
              'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
              'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
              'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
              'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
              'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
              'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
              'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=']
    key = token_bytes(AES.block_size)
    nonce = b'\x00' * (AES.block_size // 2)
    ciphertexts = []
    for based in baseds:
        aes_ctr = AES.new(key, MODE_CTR, nonce=nonce)
        plaintext = b64decode(based)
        ciphertext = aes_ctr.encrypt(plaintext)
        ciphertexts.append(aes_ctr.nonce + ciphertext)
    return ciphertexts


def main():
    # Test that the oracle's output is from a stream cipher.
    ciphertexts = oracle()
    ciphertexts_len = len(ciphertexts)
    ciphertexts_sizes = set()
    for ciphertext in ciphertexts:
        ciphertext_len = len(ciphertext)
        ciphertexts_sizes.add(ciphertext_len)
    ciphertexts_sizes = sorted(ciphertexts_sizes, reverse=True)
    try:
        for index in range(ciphertexts_len - 1):
            # There must be a difference in size of one byte.
            if ciphertexts_sizes[index] - ciphertexts_sizes[index + 1] == 1:
                raise StopIteration
        print('Probably not a stream cipher!')
        return
    except StopIteration:
        pass
    # For a fixed nonce, the first n bytes are the same for all ciphertexts.
    shortest = min(ciphertexts, key=len)
    shortest_len = len(shortest)
    nonce_len = 0
    try:
        for index_1 in range(shortest_len):
            for index_2 in range(ciphertexts_len - 1):
                if ciphertexts[index_2][index_1] != ciphertexts[index_2 + 1][index_1]:
                    raise StopIteration
            nonce_len = nonce_len + 1
    except StopIteration:
        pass
    if nonce_len == 0:
        print('No nonce?!')
        return
    # You can reasonably assume that at each position after the first non-nonce byte, the most common character across
    # every line is " ", and see what happens!
    space = b' '
    key = b''
    for index in range(nonce_len, shortest_len):
        values = []
        for ciphertext in ciphertexts:
            values.append(ciphertext[index])
        counted = Counter(values)
        commonest = counted.most_common(1)[0][0]
        candidate = xor(space, commonest)
        key = key + candidate
    # xor(key, ciphertexts[3][nonce_len:], cut='left') yields b'$,ght**+1 -cen1ury <', a useful crib as
    # b'Eighteenth-century'.
    # key = xor(b'Eighteenth-century', ciphertexts[3][nonce_len], cut='left')
    # xor(key, ciphertexts[-1][nonce_len:], cut='left') yields b'A terrible beauty ', which Google autocompletes to the
    # poem "Easter, 1916" by William Butler Yeats, whose longest line is "He, too, has been changed in his turn,".
    crib = 'He, too, has been changed in his turn,'
    longest = max(ciphertexts, key=len)
    key = xor(crib.encode(), longest[nonce_len:])
    for ciphertext in ciphertexts:
        plaintext = xor(key, ciphertext[nonce_len:], cut='right')
        print(plaintext.decode())


if __name__ == '__main__':
    main()
