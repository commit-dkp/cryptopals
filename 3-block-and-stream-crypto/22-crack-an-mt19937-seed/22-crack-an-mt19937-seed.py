# CryptoPals Python Solutions / Set 3 / Solution 22
# Challenge in 22-crack-an-mt19937-seed.md .
#
# This challenge demonstrates the importance of seeding pseudo-random number generators (PRNGs) with secret values,
# because if you have patience, "the time at which the oracle did something" is absolutely a discoverable value. This
# weakness is not unique to the MT19937 PRNG, and applies to any PRNG, including cryptographically secure PRNGs
# (CSPRNGs).
from random import Random
from secrets import randbelow
from time import sleep, time

# MT19337 is only defined for 32-bit words.
WIDTH = 32


def oracle():
    # CryptoPals wasn't kidding when they said "go get coffee" !
    seconds_max = 1000
    seconds_min = 40
    seconds = seconds_max - randbelow(seconds_max - seconds_min + 1)
    # Instantiate your own instance of Random to get a generator that doesn't share state with Python's own hidden
    # instance.
    mt = Random()
    sleep(seconds)
    # Unix timestamps are the number of seconds since 1970-01-01T00:00:00Z.
    mt.seed(int(time()))
    sleep(seconds)
    return mt.getrandbits(WIDTH)


def main():
    start = time()
    gotrandbits = oracle()
    stop = time()
    start = int(start)
    stop = int(stop)
    # Instantiate your own instance of Random to get a generator that doesn't share state with the oracle's.
    mt = Random()
    seed = 0
    for candidate in range(start, stop + 1):
        mt.seed(candidate)
        if mt.getrandbits(WIDTH) == gotrandbits:
            seed = candidate
            break
    if seed:
        print(f'Seed: {seed}')
    else:
        print('No seed?!')


if __name__ == '__main__':
    main()
