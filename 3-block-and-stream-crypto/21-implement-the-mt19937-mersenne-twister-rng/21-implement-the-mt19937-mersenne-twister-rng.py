# CryptoPals Python Solutions / Set 3 / Solution 21
# Challenge in 21-implement-the-mt19937-mersenne-twister-rng.md .
#
# This challenge insists on writing your own MT19937 code, but it won't be necessary to reuse it for the rest of the
# exercises, where you can use Python's random library which uses MT19937 as the core generator. If you take CryptoPal's
# advice and just implement the pseudocode from Wikipedia, it will not reproduce the same values as Python's own
# implementation, and it will not pass the published test vectors.
#
# The documentation situation for MT19937 is not great, however, as it has been tweaked over time and the documentation
# for those tweaks spread out over multiple sources. The primary source is "Mersenne Twister: A 623-Dimensionally
# Equidistributed Uniform Pseudo-Random Number Generator" at https://dl.acm.org/doi/pdf/10.1145/272991.272995 , but the
# _authoritative_ source with test vectors is the C reference implementation at
# http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/MT2002/emt19937ar.html . Here, I have translated the (current?) C
# reference implementation into Python, and tried to leave it as faithfully readable as possible.
class MT19937:
    upper_mask = 0x80000000
    width_mask = 0xffffffff
    width_smol = 30
    state_size = 624
    state = [0] * state_size
    size = state_size + 1

    # For seeds with more than 32 bits.
    def init_by_array(self, inits):
        # Makoto Matsumoto's birthday!
        self.init_state(19650218)
        # Spectral-tested multipliers from The Art Of Computer Programming Volume 2.
        lj_multiplier = 1664525
        waterman_multiplier = 1566083941
        index = 1
        counter = 0
        key_length = len(inits)
        countdown = self.state_size if self.state_size > key_length else key_length
        while countdown > 0:
            self.state[index] = (self.state[index] ^ ((self.state[index - 1] ^ (
                    self.state[index - 1] >> self.width_smol)) * lj_multiplier)) + inits[counter] + counter
            self.state[index] = self.state[index] & self.width_mask
            index = index + 1
            counter = counter + 1
            if index >= self.state_size:
                self.state[0] = self.state[self.state_size - 1]
                index = 1
            if counter >= key_length:
                counter = 0
            countdown = countdown - 1
        countdown = self.state_size - 1
        while countdown > 0:
            self.state[index] = (self.state[index] ^ ((self.state[index - 1] ^ (
                    self.state[index - 1] >> self.width_smol)) * waterman_multiplier)) - index
            self.state[index] = self.state[index] & self.width_mask
            index = index + 1
            if index >= self.state_size:
                self.state[0] = self.state[self.state_size - 1]
                index = 1
            countdown = countdown - 1
        # Ensure non-zero state by setting a most significant bit of 1.
        self.state[0] = self.upper_mask

    # For seeds with 32 bits or fewer.
    def init_state(self, seed):
        self.state[0] = seed & self.width_mask
        # Another spectral-tested multiplier from The Art Of Computer Programming Volume 2.
        bn_multiplier = 1812433253
        for index in range(1, self.state_size):
            self.state[index] = (bn_multiplier * (self.state[index - 1] ^ (
                    self.state[index - 1] >> self.width_smol)) + index)
            self.state[index] = self.state[index] & self.width_mask
            self.size = index + 1

    def generate(self):
        default_seed = 5489
        shift_size = 397
        lower_mask = 0x7fffffff
        matrix = 0x9908b0df
        twister = [0x0, matrix]
        if self.size >= self.state_size:
            if self.size == self.state_size + 1:
                self.init_state(default_seed)
            counter = 0
            while counter < self.state_size - shift_size:
                generated = (self.state[counter] & self.upper_mask) | (self.state[counter + 1] & lower_mask)
                self.state[counter] = self.state[counter + shift_size] ^ (generated >> 1) ^ twister[generated & 0x1]
                counter = counter + 1
            while counter < self.state_size - 1:
                generated = (self.state[counter] & self.upper_mask) | (self.state[counter + 1] & lower_mask)
                self.state[counter] = self.state[counter + (shift_size - self.state_size)] ^ (generated >> 1) ^ twister[
                    generated & 0x1]
                counter = counter + 1
            generated = (self.state[self.state_size - 1] & self.upper_mask) | (self.state[0] & lower_mask)
            self.state[self.state_size - 1] = self.state[shift_size - 1] ^ (generated >> 1) ^ twister[generated & 0x1]
            self.size = 0
        generated = self.state[self.size]
        self.size = self.size + 1
        # Tempering shifts and masks.
        generated = generated ^ (generated >> 11)
        generated = generated ^ (generated << 7) & 0x9d2c5680
        generated = generated ^ (generated << 15) & 0xefc60000
        generated = generated ^ (generated >> 18)
        return generated


def main():
    mt = MT19937()
    inits = [0x123, 0x234, 0x345, 0x456]
    mt.init_by_array(inits)
    # Test vectors from http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/MT2002/CODES/mt19937ar.out
    with open('21-implement-the-mt19937-mersenne-twister-rng.txt') as vectors:
        for vector in vectors:
            vectored = int(vector.rstrip())
            generated = mt.generate()
            if vectored != generated:
                print('Failed a test vector?!')
                return
    print('Passed test vectors!')


if __name__ == '__main__':
    main()
