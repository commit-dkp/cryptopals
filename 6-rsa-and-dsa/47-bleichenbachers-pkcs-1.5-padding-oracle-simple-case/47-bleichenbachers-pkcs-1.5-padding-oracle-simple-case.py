# CryptoPals Python Solutions / Set 6 / Solution 47
# Challenge in 47-bleichenbachers-pkcs-1.5-padding-oracle-simple-case.md .
#
# Because Pycryptodome doesn't support the generation of strong primes with less than 512 bits, this solution actually
# implements the "complete case" with a Step 2b and a Step 3 that handles multiple intervals. So for a bit of a
# challenge, the next solution implements the complete case with multiple optimizations to generally reduce the number
# of oracle calls by a factor of ten.
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from secrets import randbelow, token_bytes


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


def main():
    oracle = Oracle()
    ciphertext, public_exponent, composite = oracle.encrypt()
    composite_len = len(ciphertext)
    ciphertext = int.from_bytes(ciphertext, 'big')
    calls = 0
    counter = 1
    block = 2 ** (8 * (composite_len - 2))
    message_interval = [(2 * block, 3 * block - 1)]
    # Step 1: Blinding (Only needed for computing signatures where the message does not conform to the proper padding).
    while True:
        step = randbelow(composite - 2) + 1
        query_step = pow(step, public_exponent, composite)
        query = (ciphertext * query_step) % composite
        query = query.to_bytes(composite_len, 'big')
        calls = calls + 1
        if oracle.decrypt(query):
            break
    # Step 2: Searching for PKCS conforming messages.
    while True:
        # Step 2a: Starting the search.
        if counter == 1:
            step = (composite + 3 * block - 1) // (3 * block)
            while True:
                query_step = pow(step, public_exponent, composite)
                query = (ciphertext * query_step) % composite
                query = query.to_bytes(composite_len, 'big')
                calls = calls + 1
                if oracle.decrypt(query):
                    break
                step = step + 1
        # Step 2b: Searching with more than one interval left.
        elif len(message_interval) > 1:
            while True:
                step = step + 1
                query_step = pow(step, public_exponent, composite)
                query = (ciphertext * query_step) % composite
                query = query.to_bytes(composite_len, 'big')
                calls = calls + 1
                if oracle.decrypt(query):
                    break
        # Step 2c: Searching with one interval left.
        elif len(message_interval) == 1:
            lower_bound, upper_bound = message_interval[0]
            # Step 4: Computing the solution.
            if lower_bound == upper_bound:
                message = lower_bound.to_bytes(composite_len, 'big')
                message = message[message.find(b'\x00', 2) + 1:]
                break
            bb_r = ((2 * (upper_bound * step - 2 * block)) + composite - 1) // composite
            step = ((2 * block + bb_r * composite) + upper_bound - 1) // upper_bound
            while True:
                query_step = pow(step, public_exponent, composite)
                query = (ciphertext * query_step) % composite
                query = query.to_bytes(composite_len, 'big')
                calls = calls + 1
                if oracle.decrypt(query):
                    break
                step = step + 1
                if step > (3 * block + bb_r * composite) // lower_bound:
                    bb_r = bb_r + 1
                    step = ((2 * block + bb_r * composite) + upper_bound - 1) // upper_bound
        # Step 3: Narrowing the set of solutions.
        message_interval_new = []
        for lower_bound, upper_bound in message_interval:
            min_r = ((lower_bound * step - 3 * block + 1) + composite - 1) // composite
            max_r = (upper_bound * step - 2 * block) // composite
            for bb_r in range(min_r, max_r + 1):
                l_b = max(lower_bound, ((2 * block + bb_r * composite) + step - 1) // step)
                u_b = min(upper_bound, (3 * block - 1 + bb_r * composite) // step)
                if l_b > u_b:
                    print("In Step 3, l_b can't be greater than u_b!")
                    return
                for index, (lower, upper) in enumerate(message_interval_new):
                    # If there is an overlap, then replace the boundaries of the overlapping
                    # interval with the wider (or equal) boundaries of the new merged interval
                    if not (upper < l_b or lower > u_b):
                        new_a = min(l_b, lower)
                        new_b = max(u_b, upper)
                        message_interval_new[index] = new_a, new_b
                        break
                message_interval_new.append((l_b, u_b))
        if len(message_interval_new) == 0:
            print("In Step 3, message_interval_new can't have zero intervals!")
            return
        message_interval = message_interval_new
        counter = counter + 1
    print(f'"{message.decode()}" in {calls} calls!')


if __name__ == '__main__':
    main()
