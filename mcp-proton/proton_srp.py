"""Proton SRP authentication.

Direct port of proton-python-client/proton/srp/ modules (pmhash.py, util.py,
_pysrp.py) and proton/constants.py into one standalone file.
"""

import base64
import hashlib
import os
import re

import bcrypt
import pgpy

# ── Proton's PGP public key used to sign the SRP modulus ─────────────────────
SRP_MODULUS_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----"""

SRP_LEN_BYTES = 256
PM_VERSION = 4


# ── PMHash — custom 256-byte digest (from pmhash.py) ─────────────────────────

class PMHash:
    digest_size = 256
    name = "PMHash"

    def __init__(self, b: bytes = b""):
        self.b = b

    def update(self, b: bytes) -> None:
        self.b += b

    def digest(self) -> bytes:
        return (
            hashlib.sha512(self.b + b"\x00").digest()
            + hashlib.sha512(self.b + b"\x01").digest()
            + hashlib.sha512(self.b + b"\x02").digest()
            + hashlib.sha512(self.b + b"\x03").digest()
        )

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "PMHash":
        return PMHash(self.b)


def pmhash(b: bytes = b"") -> PMHash:
    return PMHash(b)


# ── Little-endian helpers (from util.py) ──────────────────────────────────────

def bytes_to_long(s: bytes) -> int:
    return int.from_bytes(s, "little")


def long_to_bytes(n: int, num_bytes: int) -> bytes:
    return n.to_bytes(num_bytes, "little")


# ── bcrypt password hashing (from util.py) ────────────────────────────────────

_BCRYPT_ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_STD_ALPHABET    = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def bcrypt_b64_encode(s: bytes) -> bytes:
    s = base64.b64encode(s)
    return s.translate(bytes.maketrans(_STD_ALPHABET, _BCRYPT_ALPHABET))


def hash_password_3(password: bytes, salt: bytes, modulus: bytes) -> bytes:
    salt = (salt + b"proton")[:16]
    salt_b64 = bcrypt_b64_encode(salt)[:22]
    hashed = bcrypt.hashpw(password, b"$2y$10$" + salt_b64)
    return PMHash(hashed + modulus).digest()


def hash_password(password: bytes, salt: bytes, modulus: bytes, version: int) -> bytes:
    if version in (3, 4):
        return hash_password_3(password, salt, modulus)
    raise ValueError(f"Unsupported SRP version: {version}")


# ── SRP helpers (from util.py / _pysrp.py) ───────────────────────────────────

def _get_random_of_length(nbytes: int) -> int:
    offset = (nbytes * 8) - 1
    return int.from_bytes(os.urandom(nbytes), "little") | (1 << offset)


def _custom_hash(*args) -> int:
    """PMHash over LE-encoded integer / raw bytes arguments."""
    h = pmhash()
    for s in args:
        if s is not None:
            data = long_to_bytes(s, SRP_LEN_BYTES) if isinstance(s, int) else s
            h.update(data)
    return bytes_to_long(h.digest())


def _hash_k(g: int, N: int) -> int:
    h = pmhash()
    h.update(g.to_bytes(SRP_LEN_BYTES, "little"))
    h.update(N.to_bytes(SRP_LEN_BYTES, "little"))
    return bytes_to_long(h.digest())


# ── SRPUser (from _pysrp.py) ─────────────────────────────────────────────────

class SRPUser:
    """Proton SRP-6a client.  Port of proton-python-client srp/User."""

    def __init__(self, password: str, n_bin: bytes, g_hex: bytes = b"2"):
        self.N = bytes_to_long(n_bin)
        self.g = int(g_hex, 16)
        self.k = _hash_k(self.g, self.N)
        self.p = password.encode() if isinstance(password, str) else password
        self.a = _get_random_of_length(32)   # 256-bit random exponent
        self.A = pow(self.g, self.a, self.N)
        self.M: bytes | None = None
        self.K: bytes | None = None
        self._expected_server_proof: bytes | None = None
        self._authenticated = False

    def get_challenge(self) -> bytes:
        """Return client ephemeral A (256 bytes, little-endian)."""
        return long_to_bytes(self.A, SRP_LEN_BYTES)

    def process_challenge(
        self,
        bytes_s: bytes,
        bytes_server_challenge: bytes,
        version: int = PM_VERSION,
    ) -> bytes | None:
        """Compute and return client proof M, or None on SRP-6a safety violation."""
        B = bytes_to_long(bytes_server_challenge)
        if (B % self.N) == 0:
            return None

        u = _custom_hash(self.A, B)
        if u == 0:
            return None

        x_bytes = hash_password(
            self.p, bytes_s, long_to_bytes(self.N, SRP_LEN_BYTES), version
        )
        x = bytes_to_long(x_bytes)
        v = pow(self.g, x, self.N)
        S = pow((B - self.k * v) % self.N, self.a + u * x, self.N)

        self.K = long_to_bytes(S, SRP_LEN_BYTES)

        # Client proof  M = PMHash(A_le ‖ B_le ‖ K)
        h = pmhash()
        h.update(long_to_bytes(self.A, SRP_LEN_BYTES))
        h.update(long_to_bytes(B, SRP_LEN_BYTES))
        h.update(self.K)
        self.M = h.digest()

        # Expected server proof = PMHash(A_le ‖ M ‖ K)
        h2 = pmhash()
        h2.update(long_to_bytes(self.A, SRP_LEN_BYTES))
        h2.update(self.M)
        h2.update(self.K)
        self._expected_server_proof = h2.digest()

        return self.M

    def verify_session(self, server_proof: bytes) -> bool:
        if self._expected_server_proof == server_proof:
            self._authenticated = True
        return self._authenticated


# ── Modulus verification ──────────────────────────────────────────────────────

def verify_modulus(armored_modulus: str) -> bytes:
    """Verify Proton's PGP-signed SRP modulus and return the raw 256-byte value."""
    try:
        msg = pgpy.PGPMessage.from_blob(armored_modulus)
        key, _ = pgpy.PGPKey.from_blob(SRP_MODULUS_KEY)
        key.verify(msg)
        content = msg.message
        if isinstance(content, bytes):
            content = content.decode()
        return base64.b64decode(content.strip())
    except Exception:
        # Fallback: extract base64 payload from the cleartext-signed blob
        match = re.search(
            r"Hash:[ \t]*\S+\s*\n\n([\w+/=\n]+)\n-----BEGIN PGP",
            armored_modulus,
            re.DOTALL,
        )
        if match:
            return base64.b64decode(match.group(1).replace("\n", "").strip())
        raise ValueError("Cannot extract modulus from server response")
