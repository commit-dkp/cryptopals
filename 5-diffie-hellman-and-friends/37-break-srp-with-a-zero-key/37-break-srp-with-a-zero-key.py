# CryptoPals Python Solutions / Set 5 / Solution 37
# Challenge in 37-break-srp-with-a-zero-key.md .
#
# This challenge just demonstrates how, being built on top of Diffie-Hellman, SRP also has to be careful about insecure
# parameter negotiation. Parameter negotiation has been the Achilles' heel of many protocols, leading modern protocols
# to prefer versioning instead of negotiation.
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes
from secrets import choice, compare_digest, randbits, token_bytes


class DH:
    def __init__(self, base, modulus):
        self.base = base
        self.modulus = modulus
        self.private_value = randbits(1024) % self.modulus
        self.public_value = pow(base, self.private_value, self.modulus)


def main():
    # SRP group parameters from https://www.rfc-editor.org/rfc/rfc5054#appendix-A . Note that standard Diffie-Hellman
    # group parameters can't be safely reused in SRP. They will not generate the entire group, and so an attacker may
    # eliminate many possible values of the client exponent from a single exchange.
    base = 2
    modulus = int('9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea'
                  '9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0'
                  'd0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b979891'
                  '49b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158b'
                  'fd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437'
                  'd6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b529'
                  '2e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf7'
                  '6e3fed135f9bb', 16)
    # Prevents a malicious server from guessing two passwords per exchange. In the "6a" version of the SRP
    # specification, this is defined as hash(modulus, base), so that if the base and modulus values can be maliciously
    # chosen by the server, the server will still need to find the discrete log of the hash-as-integer.
    two_for_one = 3
    # The client registers by sending a salt and an exponent.
    good_client = DH(base, modulus)
    good_client.salt = token_bytes(SHA256.block_size)
    good_client.identity = 'cryptopal@example.com'
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    good_client.password = choice(words_split)
    # Binding the identity prevents a malicious server from trying to discover if two users share the same password.
    # This requirement is noticeably absent in the "6a" version of the SRP specification, however.
    good_client.exponent = SHA256.new(
        good_client.salt + good_client.identity.encode() + good_client.password.encode()).digest()
    good_client.exponent = int.from_bytes(good_client.exponent, 'big')
    # The server registers the client.
    server = DH(base, modulus)
    server.client_salt = good_client.salt
    server.verifier = pow(base, good_client.exponent, modulus)
    server.public_value = (two_for_one * server.verifier + pow(base, server.private_value, modulus)) % modulus
    # Later, a bad client sends its identity and its public value. Contrary to the SRP 6a specification, this server
    # will accept zero for the bad client's public value.
    bad_client = DH(base, modulus)
    bad_client.identity = 'cryptopal@example.com'
    bad_client.public_value = 0
    server.client_identity = bad_client.identity
    server.client_public = bad_client.public_value
    # The server responds with the client's registered salt and the server's public value.
    bad_client.server_salt = server.client_salt
    bad_client.server_public = server.public_value
    if bad_client.server_public % modulus == 0:
        raise ValueError
    # The client calculate the shared random scrambling parameter.
    bad_client.public_bytes = long_to_bytes(bad_client.public_value)
    bad_client.server_bytes = long_to_bytes(bad_client.server_public)
    bad_client.scrambler = SHA256.new(bad_client.public_bytes + bad_client.server_bytes).digest()
    bad_client.scrambler = int.from_bytes(bad_client.scrambler, 'big')
    if bad_client.scrambler == 0:
        raise ValueError
    # At the same time, the server calculates the shared random scrambling parameter.
    server.client_bytes = long_to_bytes(server.client_public)
    server.public_bytes = long_to_bytes(server.public_value)
    server.scrambler = SHA256.new(server.client_bytes + server.public_bytes).digest()
    server.scrambler = int.from_bytes(server.scrambler, 'big')
    # The client calculates its session key and proof. It knows the server's session key will be zero.
    bad_client.session_key = b'\x00'
    bad_client.proof = SHA256.new(bad_client.public_bytes + bad_client.server_bytes + bad_client.session_key).digest()
    # At the same time, the server calculates its session key.
    server.session_key = pow(server.client_public * pow(server.verifier, server.scrambler, modulus),
                             server.private_value, modulus)
    server.session_key = long_to_bytes(server.session_key)
    # The client sends its session key proof, the server verifies it, and optionally sends its own proof.
    server.client_proof = bad_client.proof
    server.proof_verifier = SHA256.new(server.client_bytes + server.public_bytes + server.session_key).digest()
    if compare_digest(server.client_proof, server.proof_verifier):
        print('The server verified the bad client with a zero key!')
    else:
        print("The server couldn't verify the bad client!")
        return
    server.proof = SHA256.new(server.client_bytes + server.client_proof + server.session_key).digest()
    # The client verifies the server's session key proof.
    bad_client.server_proof = server.proof
    bad_client.verifier = SHA256.new(bad_client.public_bytes + bad_client.proof + bad_client.session_key).digest()
    if compare_digest(bad_client.server_proof, bad_client.verifier):
        print('The bad client verified the server!')
    else:
        print("The bad client couldn't verify the server!")
    # The session key is a random group element, but it is not a uniformly random byte object; some of its bytes
    # may be more likely than others. The SRP standard to "just hash it" rests on the special assumption that a
    # cryptographic hash can extract pseudorandom bits from the shared secret. In "Cryptographic Extraction And Key
    # Derivation: The HKDF Scheme" at https://eprint.iacr.org/2010/264.pdf, the author suggests this could never be
    # sufficiently proven and designs a key derivation function based on HMACs with formal proofs of its security.
    server.secret_key = SHA256.new(server.session_key).digest()
    # Hopefully the bad client doesn't need the secret key to be secure, because anyone else who observed their public
    # value of zero can derive the secret key, too.
    bad_client.secret_key = SHA256.new(bad_client.session_key).digest()


if __name__ == '__main__':
    main()
