# Don't trust me with cryptography.

"""
Implementation of https://gist.github.com/phyro/4d7bbcaad94a092eaebd984e2b9263a3 (by the same amateur).

This is an attempt at producing the simplest possible VRF function. It tries to achieve this by being
an almost direct derivation from a Schnorr signature generation and verification.

We use the Committed R-point signatures trick from Discrete log contracts [1] and define a public key PK as
a pair (X, R) where both X and R are encoded as x*G and neither is 0*G. The R part plays a role of a nonce
in the Schnorr signature. This gives us a deterministic signature s for a given message M at the cost that
we can only show one signature with this pubkey pair otherwise we'd reveal X and R.

[1] https://adiabat.github.io/dlc.pdf
"""

import hashlib
from ecc.curve import secp256k1
from ecc.key import gen_keypair


# Curve generator G
G = secp256k1.G

# Pubkey PK is a pair of two curve points X and R
class PubKey:
    def __init__(self, X, R):
        self.X = X
        self.R = R


class PrivKey:
    def __init__(self, x, r):
        self.x = x
        self.r = r
        self.X = x*G
        self.R = r*G
    
    @classmethod
    def generate(cls):
        """Generates a new keypair."""
        x, X = gen_keypair(secp256k1)
        r, R = gen_keypair(secp256k1)
        return cls(x, r)

    def to_pub(self):
        """Transform to public key."""
        return PubKey(self.X, self.R)
    

def H(x):
    """Returns the result of a hash function for input 'x'."""
    return hashlib.sha256(str(x).encode("utf-8")).hexdigest()

def rand_msg():
    """Returns a random string."""
    return H(gen_keypair(secp256k1)[0])


class VRF:

    @classmethod
    def prove(cls, alpha, SK):
        """Compute VRF on message 'alpha' and return proof and the new VRF."""
        M = alpha
        pi, _ = Schnorr.sign(SK.x, M, r=SK.r)          # Compute signature 's' which is our deterministic proof 'pi'
        beta = H(str(alpha) + str(pi))                 # To achieve a random beta output, we hash the secret and alpha

        s2, R2, new_PK = cls._next_vrf(SK)             # Compute the next VRF PK
        return beta, pi, s2, R2, new_PK

    @staticmethod
    def verify(PK, alpha, pi):
        """Verify VRF computation of message 'alpha' for pubkey PK from proof 'pi'."""
        if not Schnorr.verify(PK.X, alpha, pi, PK.R):  # schnorr.verify(X, M, s, R)
            return False

        beta = H(str(alpha) + str(pi))                 # Compute beta from VRF proof for alpha
        return beta

    # The pubkey PK can only be used once because it has a fixed nonce. But we can, along with the VRF proof
    # pi, show a new pubkey which makes the VRF output a pair (pi, PK2). To prevent someone tampering with
    # new PK2, we provide a signature signing the message M = PK2 with a temporary pubkey (X, R2) which
    # proves we know the secret key of X which is a part of our original PK.

    # Generate the pubkey for the next VRF along with the signature.
    @staticmethod
    def _next_vrf(SK):
        """Generate a new pubkey pair and sign it."""
        # NOTE: We could force the user to randomly generate the next VRF. To do that, the point (new_X, new_R)
        # that is signed is merely a point from which the next VRF is derived in the following way:
        # new_X = new_X + int(H(new_X || new_R || beta || 1))*G
        # new_R = new_R + int(H(new_X || new_R || beta || 2))*G
        # The verifier computes the new VRF which could not have been set by prover to get a preset points.

        new_SK = PrivKey.generate()
        new_PK = new_SK.to_pub()
        # Sign the new pubkey pair to prevent tampering
        M = str(new_PK.X) + str(new_PK.R)
        s, R = Schnorr.sign(SK.x, M)
        return s, R, new_SK


class Schnorr:
    # e*X + R = s*G                                    # Schnorr signature verification formula

    @classmethod
    def sign(cls, x, M, r=None):
        """Sign message M with private key x. We support passing a specific nonce scalar."""
        X = x*G
        if r is None:
            r, R = gen_keypair(secp256k1)              # We use a random nonce for this signature
        else: 
            R = r*G
        e = cls.challenge(M, X, R)                     # Compute Schnorr challenge
        s = e*x + r
        return s, R

    @classmethod
    def verify(cls, X, M, s, R):
        """Verify signature on message M by public key X."""
        e = cls.challenge(M, X, R)                     # Compute Schnorr challenge
        return e*X + R == s*G

    @staticmethod
    def challenge(M, X, R):
        """Computes the Schnorr challenge."""
        return int(H(str(M) + str(X) + str(R)), 16)


####  Tests

# Generate two curve points that make up the pubkey
SK = PrivKey.generate()

alpha = rand_msg()
beta, pi, s2, R2, new_SK = VRF.prove(alpha, SK)
PK = SK.to_pub()
# Error: Verify against wrong alpha
assert VRF.verify(PK, "nope", pi) == False
# Error: Verify against wrong proof pi
assert VRF.verify(PK, alpha, 123) == False
# Pass: Verify against correct data
assert VRF.verify(PK, alpha, pi) == beta
print(beta, pi)

# Verify schnorr signature for next VRF
# Error: Verify against wrong message
new_PK = new_SK.to_pub()
M = str(new_PK.X) + str(new_PK.R)
assert Schnorr.verify(PK.X, "nope", s2, R2) == False
# Error: Verify against wrong nonce
assert Schnorr.verify(PK.X, M, s2, PK.R) == False
# Pass: Verify against correct data
assert Schnorr.verify(PK.X, M, s2, R2) == True

# Test next VRF evaluation
alpha = rand_msg()
beta, pi, s, R2, new_SK2 = VRF.prove(alpha, new_SK)
assert VRF.verify(new_SK.to_pub(), alpha, pi) == beta
print(beta, pi)
