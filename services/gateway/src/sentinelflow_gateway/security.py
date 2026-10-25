"""API key generation and verification.

Keys look like ``sf_<43 url-safe chars>`` (256 bits of entropy). We store a
12-character lookup prefix and a SHA-256 hash; because the keys are random and
high-entropy, a fast hash is appropriate (a slow KDF is only needed for
low-entropy secrets like passwords).
"""

import hashlib
import secrets
from dataclasses import dataclass

KEY_SCHEME = "sf_"
_PREFIX_LEN = 12
_MIN_KEY_LEN = len(KEY_SCHEME) + 32


@dataclass(frozen=True)
class GeneratedKey:
    plaintext: str
    prefix: str
    key_hash: str


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def lookup_prefix(key: str) -> str:
    return key[len(KEY_SCHEME) : len(KEY_SCHEME) + _PREFIX_LEN]


def is_well_formed(key: str) -> bool:
    return key.startswith(KEY_SCHEME) and len(key) >= _MIN_KEY_LEN


def generate_api_key() -> GeneratedKey:
    plaintext = KEY_SCHEME + secrets.token_urlsafe(32)
    return GeneratedKey(plaintext, lookup_prefix(plaintext), hash_key(plaintext))


def verify_key(key: str, expected_hash: str) -> bool:
    return secrets.compare_digest(hash_key(key), expected_hash)
