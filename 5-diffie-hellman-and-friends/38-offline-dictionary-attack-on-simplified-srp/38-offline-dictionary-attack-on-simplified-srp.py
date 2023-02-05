# CryptoPals Python Solutions / Set 5 / Solution 38
# Challenge in 38-offline-dictionary-attack-on-simplified-srp.md .
#
# SRP clients can't verify the SRP server until after the client has sent its session key proof, which is sufficient to
# enable a malicious server to crack the client's password. If the client isn't expecting the server to return its own
# session key proof, the server can crack the password offline; if the client is expecting the server to return its own
# session key proof, then trying to crack the password online will add noticeable delays.
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
    client = DH(base, modulus)
    client.salt = token_bytes(SHA256.block_size)
    client.identity = 'cryptopal@example.com'
    with open('/usr/share/dict/words', 'r') as words:
        words_split = words.read().split()
    # For faster results...
    # client.password = 'aardvark'
    client.password = choice(words_split)
    # Binding the identity prevents a malicious server from trying to discover if two users share the same password.
    # This requirement is noticeably absent in the "6a" version of the SRP specification, however.
    client.exponent = SHA256.new(client.salt + client.identity.encode() + client.password.encode()).digest()
    client.exponent = int.from_bytes(client.exponent, 'big')
    # The server registers the client.
    good_server = DH(base, modulus)
    good_server.client_salt = client.salt
    good_server.verifier = pow(base, client.exponent, modulus)
    good_server.public_value = (two_for_one *
                                good_server.verifier + pow(base, good_server.private_value, modulus)) % modulus
    # Later, the client sends its identity and its public value to the bad server.
    bad_server = DH(base, modulus)
    # "Simplified" SRP where the server's public value isn't derived from the verifier.
    bad_server.public_value = (two_for_one + bad_server.public_value) % modulus
    bad_server.client_salt = token_bytes(SHA256.block_size)
    bad_server.client_identity = client.identity
    bad_server.client_public = client.public_value
    if bad_server.client_public % modulus == 0:
        raise ValueError
    # The bad server responds with a random salt and the bad server's public value.
    client.server_salt = bad_server.client_salt
    client.server_public = bad_server.public_value
    if client.server_public % modulus == 0:
        raise ValueError
    # The client calculate the shared random scrambling parameter.
    client.public_bytes = long_to_bytes(client.public_value)
    client.server_bytes = long_to_bytes(client.server_public)
    client.scrambler = SHA256.new(client.public_bytes + client.server_bytes).digest()
    client.scrambler = int.from_bytes(client.scrambler, 'big')
    if client.scrambler == 0:
        raise ValueError
    # At the same time, the server calculates the shared random scrambling parameter.
    bad_server.client_bytes = long_to_bytes(bad_server.client_public)
    bad_server.public_bytes = long_to_bytes(bad_server.public_value)
    bad_server.scrambler = SHA256.new(bad_server.client_bytes + bad_server.public_bytes).digest()
    bad_server.scrambler = int.from_bytes(bad_server.scrambler, 'big')
    # The client calculates its session key and proof.
    client.exponent = SHA256.new(client.server_salt + client.identity.encode() + client.password.encode()).digest()
    client.exponent = int.from_bytes(client.exponent, 'big')
    client.session_key = pow(client.server_public - two_for_one,
                             client.private_value + client.scrambler * client.exponent, modulus)
    client.session_key = long_to_bytes(client.session_key)
    client.proof = SHA256.new(client.public_bytes + client.server_bytes + client.session_key).digest()
    # The client sends its session key proof, the bad server cracks the password, and optionally sends its own proof.
    bad_server.client_proof = client.proof
    for word in words_split:
        # The bad server generates the password verifier.
        bad_server.client_exponent = SHA256.new(
            bad_server.client_salt + bad_server.client_identity.encode() + word.encode()).digest()
        bad_server.client_exponent = int.from_bytes(bad_server.client_exponent, 'big')
        bad_server.verifier = pow(base, bad_server.client_exponent, modulus)
        # The bad server calculates its session key.
        bad_server.session_key = pow(bad_server.client_public * pow(bad_server.verifier, bad_server.scrambler, modulus),
                                     bad_server.private_value, modulus)
        bad_server.session_key = long_to_bytes(bad_server.session_key)
        # The bad server verifies the client's session key proof.
        bad_server.proof = SHA256.new(
            bad_server.client_bytes + bad_server.public_bytes + bad_server.session_key).digest()
        if compare_digest(bad_server.proof, bad_server.client_proof):
            print(f'The client\'s password is "{word}"!')
            break
    bad_server.proof = SHA256.new(bad_server.client_bytes + bad_server.client_proof + bad_server.session_key).digest()
    # The client verifies the server's session key proof. The fact that the server did not start with a verifier for the
    # client is not detectable.
    client.server_proof = bad_server.proof
    client.verifier = SHA256.new(client.public_bytes + client.proof + client.session_key).digest()
    if compare_digest(client.server_proof, client.verifier):
        print('The client verified the bad server!')
    else:
        print("The client couldn't verify the bad server!")
    # The session key is a random group element, but it is not a uniformly random byte object; some of its bytes
    # may be more likely than others. The SRP standard to "just hash it" rests on the special assumption that a
    # cryptographic hash can extract pseudorandom bits from the shared secret. In "Cryptographic Extraction And Key
    # Derivation: The HKDF Scheme" at https://eprint.iacr.org/2010/264.pdf, the author suggests this could never be
    # sufficiently proven and designs a key derivation function based on HMACs with formal proofs of its security.
    client.secret_key = SHA256.new(client.session_key).digest()
    bad_server.secret_key = SHA256.new(bad_server.session_key).digest()


if __name__ == '__main__':
    main()
