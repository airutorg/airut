# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""DKIM signing for tests.

A key generated once per test run signs messages as any domain, and
``lookup`` stands in for DNS, serving the key's public half at
``test._domainkey.<domain>``.
"""

import base64
import functools
import secrets

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


#: Selector the test key is published under.
SELECTOR = "test"

#: Header fields signed by default: those a signer such as Gmail covers.
SIGNED_HEADERS = (
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "message-id",
    "in-reply-to",
    "references",
    "mime-version",
)


@functools.cache
def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _is_probable_prime(n: int) -> bool:
    """Miller-Rabin primality test."""
    if n % 2 == 0:
        return n == 2
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(32):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


@functools.cache
def small_key() -> rsa.RSAPrivateKey:
    """A 512-bit key, shorter than verifiers accept.

    ``cryptography`` will not generate one, but loads one built from its
    numbers.
    """
    e = 65537
    while True:
        p, q = _prime(256), _prime(256)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            break
    d = pow(e, -1, phi)
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e, p * q),
    )
    return numbers.private_key()


def private_pem(key: rsa.RSAPrivateKey | None = None) -> bytes:
    """The signing key (by default, the test key) as PEM."""
    return (key or _key()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def public_record(key: rsa.RSAPrivateKey | None = None) -> bytes:
    """The DNS TXT record publishing a key (by default, the test key)."""
    der = (
        (key or _key())
        .public_key()
        .public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return b"v=DKIM1; k=rsa; p=" + base64.b64encode(der)


def sign(
    raw: bytes,
    domain: str,
    *,
    headers: tuple[str, ...] = SIGNED_HEADERS,
    length: bool = False,
    selector: str = SELECTOR,
    key: rsa.RSAPrivateKey | None = None,
) -> bytes:
    """Return *raw* with a DKIM signature by *domain* prepended."""
    signature = dkim.sign(
        raw,
        selector.encode(),
        domain.encode(),
        private_pem(key),
        include_headers=[h.encode() for h in headers],
        canonicalize=(b"relaxed", b"relaxed"),
        length=length,
    )
    return signature + raw


def lookup(name: bytes, timeout: int = 5) -> bytes | None:
    """Serve the test key at ``test._domainkey.<any domain>``."""
    if name.startswith(f"{SELECTOR}._domainkey.".encode()):
        return public_record()
    return None
