# CTR bitflipping

There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is
susceptible.

Re-implement
[the CBC bitflipping exercise from earlier](../../2-block-crypto/16-cbc-bit-flipping-attacks/16-cbc-bit-flipping-attacks.md)
to use CTR mode instead of CBC mode. Inject an "admin=true" token.
