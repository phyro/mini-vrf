# One-time VRF

**The author is NOT a cryptographer and has not tested the libraries used or the code nor has anyone reviewed the work. This means it's very likely a fatal flaw somewhere. This is meant only as an experiment and should not be used in production.**

_NOTE: This is technically not a VRF because it changes the public key for every computation. But it may be enough for something like cryptographic sortition._

This is an implementation of a minimal one-time VRF as [explained here (by the same amateur)](https://gist.github.com/phyro/4d7bbcaad94a092eaebd984e2b9263a3).

Schnorr signature is the simplest/minimal signature. The idea is to define a VRF function which is almost equivalent to Schnorr signature. Computing a VRF output is almost equivalent to signing a Schnorr message. Similarly, verifying a VRF output is almost identical to signature verification.

#### Requirements

The only dependency is ecc-pycrypto. Please visit https://github.com/lc6chang/ecc-pycrypto and follow installation instructions.
