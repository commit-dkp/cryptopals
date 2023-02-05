# CryptoPals Python Solutions / Set 3 / Solution 23
# Challenge in 23-clone-an-mt19937-rng-from-its-output.md .
#
# For a PRNG to be considered cryptographically secure, you must not be able to predict its future values from its
# past values nor extend from its current state into past values. This challenge demonstrates how the MT19937 RNG fails
# to meet both requirements. You can use the past values to recover its state, predict its future values, and of course
# also rewind that state to obtain even more past values. You can even train a computer to clone it! More at
# https://research.nccgroup.com/2021/10/18/cracking-random-number-generators-using-machine-learning-part-2-mersenne-twister/
from pwnlib.util.fiddling import bits, unbits
from random import Random

# MT19337 is only defined for 32-bit words.
WIDTH = 32


class Oracle:
    def __init__(self):
        self.mt = Random()

    def getrandbits(self, randbits_inner):
        return self.mt.getrandbits(randbits_inner)


def untemper(gotrandbits, direction, shift, mask=0xffffffff):
    gotrandbits = bits(gotrandbits)
    gotrandbits_len = len(gotrandbits)
    # Python integers do not have a fixed width, and may be less than 32 bits.
    if gotrandbits_len < WIDTH:
        padded = [0] * (WIDTH - gotrandbits_len)
        padded.extend(gotrandbits)
        gotrandbits = padded
    mask = bits(mask)
    if direction == 'left':
        gotrandbits.reverse()
        mask.reverse()
    untempered = [0] * WIDTH
    for index in range(WIDTH):
        if index < shift:
            untempered[index] = gotrandbits[index]
        else:
            untempered[index] = gotrandbits[index] ^ (mask[index] & untempered[index - shift])
    if direction == 'left':
        untempered.reverse()
    untempered = unbits(untempered)
    return int.from_bytes(untempered, 'big')


def main():
    print('Cloning oracle...')
    state_size = 624
    oracle = Oracle()
    cloned_state = [0] * state_size
    python_version = 3
    for index in range(state_size):
        gotrandbits = oracle.getrandbits(WIDTH)
        untempered = untemper(gotrandbits, 'right', 18)
        untempered = untemper(untempered, 'left', 15, 0xefc60000)
        untempered = untemper(untempered, 'left', 7, 0x9d2c5680)
        untempered = untemper(untempered, 'right', 11)
        cloned_state[index] = untempered
    cloned_state.append(state_size)
    cloned_state = tuple(cloned_state)
    cloned_state = (python_version, cloned_state, None)
    mt = Random()
    mt.setstate(cloned_state)
    if mt.getrandbits(WIDTH) == oracle.getrandbits(WIDTH):
        print('Oracle cloned!')
    else:
        print('Oracle not cloned?!')


if __name__ == '__main__':
    main()
