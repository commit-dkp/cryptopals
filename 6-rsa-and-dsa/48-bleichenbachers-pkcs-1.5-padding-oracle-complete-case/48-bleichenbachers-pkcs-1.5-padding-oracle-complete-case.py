# CryptoPals Python Solutions / Set 6 / Solution 48
# Challenge in 48-bleichenbachers-pkcs-1.5-padding-oracle-complete-case.md .
#
# "Chosen Ciphertext Attacks Against Protocols Based On The RSA Encryption Standard PKCS #1" by Daniel Bleichenbacher is
# also known as the Million Message Attack because, well, you have to ask the oracle to decrypt a lot of incorrect
# ciphertexts before you arrive at the correct one. The good news is that various optimizations have been proposed as
# described in "Experimenting With The Bleichenbacher Attack" at
# https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/appliedcrypto/education/theses/Experimenting%20with%20the%20Bleichenbacher%20Attack%20-%20Livia%20Capol.pdf
# and implemented here.
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from math import gcd, lcm
from secrets import token_bytes


class Oracle:
    key = RSA.generate(1024)
    keysize_bytes = key.size_in_bytes()

    def encrypt(self):
        cipher = PKCS1_v1_5.new(self.key)
        plaintext = 'kick it, CC'
        return cipher.encrypt(plaintext.encode()), self.key.e, self.key.n

    def decrypt(self, ciphertext):
        cipher = PKCS1_v1_5.new(self.key)
        sentinel = token_bytes(self.keysize_bytes)
        plaintext = cipher.decrypt(ciphertext, sentinel=sentinel, expected_pt_len=0)
        if plaintext == sentinel:
            return False
        return True


# For parallel threads, generate (step_range, step_low) values for each message interval.
def gen_state(message_intervals, step, block, composite):
    intervals_len = len(message_intervals)
    state = []
    for index in range(intervals_len):
        (lower_candidate, upper_candidate) = message_intervals[index]
        step_range = 2 * (upper_candidate * step - 2 * block + composite - 1) // composite
        step_low = (2 * block + step_range * composite + upper_candidate - 1) // upper_candidate
        new_state = (step_range, step_low)
        state.append(new_state)
    return state


def update_intervals(message_intervals, step, block, composite):
    new_intervals = []
    for (lower, upper) in message_intervals:
        range_low = (lower * step - 3 * block + 1 + composite - 1) // composite
        range_high = (upper * step - 2 * block) // composite + 1
        for step_range in range(range_low, range_high):
            interval_low = max(lower, ((2 * block + step_range * composite + step - 1) // step))
            interval_high = min(upper, (3 * block - 1 + step_range * composite) // step)
            try:
                intervals_len = len(new_intervals)
                for index in range(intervals_len):
                    (lower_candidate, upper_candidate) = new_intervals[index]
                    if (lower_candidate <= interval_high) and (upper_candidate >= interval_low):
                        new_low = min(lower_candidate, interval_low)
                        new_high = max(upper_candidate, interval_high)
                        new_intervals[index] = (new_low, new_high)
                        raise StopIteration
                interval = (interval_low, interval_high)
                new_intervals.append(interval)
            except StopIteration:
                pass
    return new_intervals


def next_step(current_step, oracle, ciphertext, public_exponent, composite, composite_len, message_intervals, block,
              calls_made, step_2b):
    lower, upper = message_intervals[0]
    step = current_step
    if not step_2b:
        step = (composite + 2 * block + upper - 1) // upper
    else:
        lower_min = upper
        upper_max = lower
        for (lower_candidate, upper_candidate) in message_intervals:
            if lower_min > lower_candidate:
                lower_min = lower_candidate
            if upper_max < upper_candidate:
                upper_max = upper_candidate
        lower = lower_min
        upper = upper_max
        step = step + ((composite + upper - 1) // upper) - 1
    index = 1
    low = (3 * block + index * composite + lower - 1) // lower
    high = ((2 * block + (index + 1) * composite + upper - 1) // upper) - 1
    while True:
        if not (index == -1):
            while True:
                # Start Skipping Holes from "Efficient Padding Oracle Attacks On Cryptographic Hardware" at
                # https://eprint.iacr.org/2012/417.pdf
                if low <= step <= high:
                    step = high + 1
                elif low > high:
                    index, low, high = -1, 0, 0
                    break
                elif step < low:
                    break
                index = index + 1
                low = (3 * block + index * composite + lower - 1) // lower
                high = ((2 * block + (index + 1) * composite + upper - 1) // upper) - 1
                # End Skipping Holes!
        step_candidate = pow(step, public_exponent, composite)
        query = (ciphertext * step_candidate) % composite
        query = query.to_bytes(composite_len, 'big')
        calls_made = calls_made + 1
        if oracle.decrypt(query):
            return step, calls_made
        step = step + 1


def find_trimmers(low_boundary, high_boundary, trimmer_inverse, oracle, ciphertext, public_exponent, composite,
                  composite_len, calls_made, find_min):
    if low_boundary >= high_boundary:
        if find_min:
            return high_boundary, calls_made
        else:
            return low_boundary, calls_made
    else:
        if find_min:
            mid = (low_boundary + high_boundary) // 2
        else:
            mid = (low_boundary + high_boundary + 1) // 2
    boundary = pow(mid, public_exponent, composite)
    query = (ciphertext * boundary * trimmer_inverse) % composite
    query = query.to_bytes(composite_len, 'big')
    calls_made = calls_made + 1
    if oracle.decrypt(query):
        if find_min:
            return find_trimmers(low_boundary, mid, trimmer_inverse, oracle, ciphertext, public_exponent, composite,
                                 composite_len, calls_made, find_min)
        else:
            return find_trimmers(mid, high_boundary, trimmer_inverse, oracle, ciphertext, public_exponent, composite,
                                 composite_len, calls_made, find_min)
    else:
        slack = 10
        if find_min:
            for slacked in range(1, slack):
                if mid - slacked >= low_boundary:
                    boundary = pow(mid - slacked, public_exponent, composite)
                    query = (ciphertext * boundary * trimmer_inverse) % composite
                    query = query.to_bytes(composite_len, 'big')
                    calls_made = calls_made + 1
                    if oracle.decrypt(query):
                        return find_trimmers(low_boundary, mid - slacked, trimmer_inverse, oracle, ciphertext,
                                             public_exponent, composite, composite_len, calls_made, find_min)
                else:
                    return find_trimmers(mid + 1, high_boundary, trimmer_inverse, oracle, ciphertext, public_exponent,
                                         composite, composite_len, calls_made, find_min)
            return find_trimmers(mid + 1, high_boundary, trimmer_inverse, oracle, ciphertext, public_exponent,
                                 composite, composite_len, calls_made, find_min)
        else:
            for slacked in range(1, slack):
                if mid + slacked <= high_boundary:
                    boundary = pow(mid + slacked, public_exponent, composite)
                    query = (ciphertext * boundary * trimmer_inverse) % composite
                    query = query.to_bytes(composite_len, 'big')
                    calls_made = calls_made + 1
                    if oracle.decrypt(query):
                        return find_trimmers(low_boundary, mid - 1, trimmer_inverse, oracle, ciphertext,
                                             public_exponent, composite, composite_len, calls_made, find_min)
                else:
                    return find_trimmers(low_boundary, mid - 1, trimmer_inverse, oracle, ciphertext, public_exponent,
                                         composite, composite_len, calls_made, find_min)
            return find_trimmers(low_boundary, mid - 1, trimmer_inverse, oracle, ciphertext, public_exponent, composite,
                                 composite_len, calls_made, find_min)


def main():
    oracle = Oracle()
    ciphertext, public_exponent, composite = oracle.encrypt()
    composite_len = len(ciphertext)
    ciphertext = int.from_bytes(ciphertext, 'big')
    block = 2 ** (8 * (composite_len - 2))
    lower_bound = 2 * block
    upper_bound = 3 * block - 1
    # Start Trimmers from "Efficient Padding Oracle Attacks On Cryptographic Hardware" at
    # https://eprint.iacr.org/2012/417.pdf
    trimmer_max = (2 * composite + 9 * block - 1) // 9 * block
    slack = 6
    calls_made = 0
    cutoff_trimming = 4000
    trimmers = []
    try:
        for trimmer in range(3, trimmer_max):
            trimmer_inverse = pow(trimmer, -public_exponent, composite)
            boundary_min = 2 * trimmer // 3 + 1
            boundary_max = (3 * trimmer + 1) // 2
            for slacked in range(1, slack):
                if trimmer - slacked < boundary_min and trimmer + slacked > boundary_max:
                    break
                if trimmer - slacked >= boundary_min and gcd(trimmer - slacked, 1) == 1:
                    calls_made = calls_made + 1
                    boundary = pow(trimmer - slacked, public_exponent, composite)
                    query = (ciphertext * boundary * trimmer_inverse) % composite
                    query = query.to_bytes(composite_len, 'big')
                    if oracle.decrypt(query):
                        trimmers.append(trimmer)
                        break
                if calls_made >= cutoff_trimming:
                    raise StopIteration
                if trimmer + slacked <= boundary_max and gcd(trimmer + slacked, trimmer) == 1:
                    calls_made = calls_made + 1
                    boundary = pow(trimmer + slacked, public_exponent, composite)
                    query = (ciphertext * boundary * trimmer_inverse) % composite
                    query = query.to_bytes(composite_len, 'big')
                    if oracle.decrypt(query):
                        trimmers.append(trimmer)
                        break
                if calls_made >= cutoff_trimming:
                    raise StopIteration
    except StopIteration:
        pass
    if trimmers:
        lcm_trimmer = lcm(*trimmers)
        lcm_trimmer_inverse = pow(lcm_trimmer, -public_exponent, composite)
        low_boundary = 2 * lcm_trimmer // 3 + 1
        high_boundary = ((3 * lcm_trimmer + 1) // 2) - 1
        low_trimmer, calls_made = find_trimmers(low_boundary, lcm_trimmer, lcm_trimmer_inverse, oracle, ciphertext,
                                                public_exponent, composite, composite_len, calls_made, find_min=True)
        high_trimmer, calls_made = find_trimmers(lcm_trimmer, high_boundary, lcm_trimmer_inverse, oracle, ciphertext,
                                                 public_exponent, composite, composite_len, calls_made, find_min=False)
        lower_bound = (lower_bound * lcm_trimmer) // low_trimmer
        upper_bound = (upper_bound * lcm_trimmer) // high_trimmer
        # End Trimmers!
    message_intervals = [(lower_bound, upper_bound)]
    # Step 2a: Starting the search.
    step, calls_made = next_step((composite + 3 * block - 1) // 3 * block, oracle, ciphertext, public_exponent,
                                 composite, composite_len, message_intervals, block, calls_made, step_2b=False)
    message_intervals = update_intervals(message_intervals, step, block, composite)
    parallel_intervals = 16000
    skip_2c = 0
    count_2c = False
    calls_2c = 0
    cutoff_2c = 2800
    experimental_tries = 5.6
    # Step 2b: Searching with more than one interval left.
    try:
        while True:
            if len(message_intervals) > 1:
                if len(message_intervals) <= parallel_intervals:
                    # Start Parallel Threads from "Attacking RSA-Based Sessions In SSL/TLS" at
                    # https://eprint.iacr.org/2003/052.pdf
                    state = gen_state(message_intervals, step, block, composite)
                    try:
                        while True:
                            for index in range(len(message_intervals)):
                                step_range = state[index][0]
                                step = state[index][1]
                                step_high = ((3 * block + step_range * composite + message_intervals[index][0] - 1) //
                                             message_intervals[index][0]) - 1
                                while step > step_high:
                                    step_range = step_range + 1
                                    step = (2 * block + step_range * composite + message_intervals[index][1] - 1) // \
                                           message_intervals[index][1]
                                    step_high = ((3 * block + step_range * composite + message_intervals[index][
                                        0] - 1) //
                                                 message_intervals[index][0]) - 1
                                step_candidate = pow(step, public_exponent, composite)
                                query = (ciphertext * step_candidate) % composite
                                query = query.to_bytes(composite_len, 'big')
                                calls_made = calls_made + 1
                                if oracle.decrypt(query):
                                    success = True
                                else:
                                    step = step + 1
                                    success = False
                                if success:
                                    message_intervals = update_intervals(message_intervals, step, block, composite)
                                    if len(message_intervals) == 1:
                                        raise StopIteration
                                    state = gen_state(message_intervals, step, block, composite)
                                    break
                                else:
                                    state[index] = (step_range, step)
                    except StopIteration:
                        pass
                    continue
                    # End Parallel Threads!
                step, calls_made = next_step(step + 1, oracle, ciphertext, public_exponent, composite, composite_len,
                                             message_intervals, block, calls_made, step_2b=True)
            # Step 2c: Searching with one interval left.
            elif len(message_intervals) == 1:
                (lower, upper) = message_intervals[0]
                # Step 4: Computing the solution.
                if lower == upper:
                    raise StopIteration
                step_range = 2 * (upper * step - 2 * block + composite - 1) // composite
                heuristic_calls = 0
                try:
                    # Start Heuristic For Step 2c from "Experimenting With The Bleichenbacher Attack" at
                    # https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/appliedcrypto/education/theses/Experimenting%20with%20the%20Bleichenbacher%20Attack%20-%20Livia%20Capol.pdf
                    while True:
                        step_low = (2 * block + step_range * composite + upper - 1) // upper
                        step_high = (3 * block + step_range * composite + lower - 1) // lower
                        for step in range(step_low, step_high):
                            if heuristic_calls > cutoff_2c:
                                print('Heuristic has encountered a very bad case, aborting.')
                                exit(1)
                            elif skip_2c > 0:
                                skip_2c = skip_2c - 1
                            else:
                                heuristic_calls = heuristic_calls + 1
                                calls_made = calls_made + 1
                                step_candidate = pow(step, public_exponent, composite)
                                query = (ciphertext * step_candidate) % composite
                                query = query.to_bytes(composite_len, 'big')
                                if oracle.decrypt(query):
                                    raise StopIteration
                        step_range = step_range + 1
                except StopIteration:
                    pass
                if heuristic_calls > 5 * experimental_tries and not count_2c:
                    count_2c = True
                elif count_2c and calls_2c == 0:
                    calls_2c = heuristic_calls
                elif count_2c and calls_2c != 0:
                    skip_2c = skip_2c + min(calls_2c, heuristic_calls) - experimental_tries
                    skip_2c = max(0, skip_2c)
                    count_2c = False
                    calls_2c = 0
                    # Stop Heuristic For Step 2c!
            # Step 3: Narrowing the set of solutions.
            message_intervals = update_intervals(message_intervals, step, block, composite)
    except StopIteration:
        pass
    message = message_intervals[0][0].to_bytes(composite_len, 'big')
    message = message[message.find(b'\x00', 2) + 1:]
    print(f'{message.decode()} in {calls_made} calls!')


if __name__ == '__main__':
    main()
