# CryptoPals Python Solutions / Set 4 / Solution 32
# Challenge in 32-break-hmac-sha1-with-a-slightly-less-artificial-timing-leak.md .
#
# You might be tempted to think that there's some way to exploit a more narrow side-channel with more complex analysis
# rather than more samples, but resist that temptation. Yes, this takes longer to exploit because it needs to take five
# times as many samples. Just let it run over-night to prove to yourself it works.
from Crypto.Hash import HMAC, SHA1
from flask import Flask, request
from requests import get
from secrets import choice, token_bytes
from threading import Thread
from time import perf_counter_ns, sleep

app = Flask(__name__)


class Oracle:
    key = token_bytes(SHA1.block_size)

    def insecure_compare(self, file, signature):
        signature = bytes.fromhex(signature)
        hmac_sha1 = HMAC.new(self.key, digestmod=SHA1)
        hmac_sha1.update(file.encode())
        digest = hmac_sha1.digest()
        for index in range(SHA1.digest_size):
            if signature[index] != digest[index]:
                return False
            # 5 milliseconds
            sleep(0.005)
        return True


@app.route('/test')
def test():
    oracle = Oracle()
    file = request.args.get('file')
    signature = request.args.get('signature')
    if oracle.insecure_compare(file, signature):
        return 'Good MAC', 200
    return 'Bad MAC', 500


def oracle_test():
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)


def main():
    Thread(target=oracle_test, daemon=True).start()
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    file = choice(words_split)
    signature = bytearray([0] * SHA1.digest_size)
    for index in range(SHA1.digest_size):
        slowest_median = 0.0
        slowest_candidate = 0
        for candidate in range(256):
            samples = 10
            signature[index] = candidate
            perfs = []
            for sample in range(samples):
                payload = {'file': file, 'signature': signature.hex()}
                start = perf_counter_ns()
                get('http://localhost:5000/test', params=payload)
                stop = perf_counter_ns()
                perfs.append(stop - start)
            perfs.sort()
            middle_sample = samples // 2
            if samples % 2 != 0:
                median = perfs[middle_sample]
            else:
                median = (perfs[middle_sample] + perfs[middle_sample - 1]) / 2
            if median > slowest_median:
                slowest_median = median
                slowest_candidate = candidate
        signature[index] = slowest_candidate
    payload = {'file': file, 'signature': signature.hex()}
    response = get('http://localhost:5000/test', params=payload)
    if response.status_code == 200:
        print('Leaked HMAC!')
    else:
        print('Too much jitter!')


if __name__ == '__main__':
    main()
