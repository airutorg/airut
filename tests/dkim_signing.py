# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""DKIM signing for tests.

Keys generated once per test run sign messages as any domain, and
``lookup`` stands in for DNS, serving their public halves: the RSA key's
at ``test._domainkey.<domain>`` and the Ed25519 key's at
``ed25519._domainkey.<domain>``.
"""

import base64
import functools
import hashlib
import secrets

import dkim
import nacl.signing
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dkim.canonicalization import CanonicalizationPolicy
from dkim.crypto import parse_pem_private_key


#: Selector the RSA test key is published under.
SELECTOR = "test"

#: Selector the Ed25519 test key is published under.
ED25519_SELECTOR = "ed25519"

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


@functools.cache
def _ed25519_key() -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey.generate()


def ed25519_record() -> bytes:
    """The DNS TXT record publishing the Ed25519 test key (RFC 8463)."""
    public = bytes(_ed25519_key().verify_key)
    return b"v=DKIM1; k=ed25519; p=" + base64.b64encode(public)


def sign_ed25519(
    raw: bytes,
    domain: str,
    *,
    headers: tuple[str, ...] = SIGNED_HEADERS,
    selector: str = ED25519_SELECTOR,
) -> bytes:
    """Return *raw* with an Ed25519 DKIM signature by *domain* prepended."""
    signature = dkim.sign(
        raw,
        selector.encode(),
        domain.encode(),
        base64.b64encode(bytes(_ed25519_key())),
        include_headers=[h.encode() for h in headers],
        canonicalize=(b"relaxed", b"relaxed"),
        signature_algorithm=b"ed25519-sha256",
    )
    return signature + raw


def sign_mislabelled(raw: bytes, domain: str, key_type: str) -> bytes:
    """Return *raw* with a signature whose ``a=`` names the other key type.

    The signature is valid, made over SHA-256 hashes with the test key of
    *key_type* (``rsa`` or ``ed25519``) and naming its selector, but its
    ``a=`` tag says the other algorithm.  ``dkim.sign`` will not make
    one, so it is built from dkimpy's internals (``gen_header``); tests
    check dkimpy verifies it, which catches a change there.
    """
    if key_type == "rsa":
        algorithm, label = b"rsa-sha256", b"ed25519-sha256"
        selector = SELECTOR
        key = parse_pem_private_key(private_pem())
    else:
        algorithm, label = b"ed25519-sha256", b"rsa-sha256"
        selector = ED25519_SELECTOR
        key = _ed25519_key()
    signer = dkim.DKIM(raw, signature_algorithm=algorithm)
    signer.hasher = hashlib.sha256
    policy = CanonicalizationPolicy.from_c_value(b"relaxed/relaxed")
    body_hash = hashlib.sha256(policy.canonicalize_body(signer.body)).digest()
    headers = tuple(h.encode() for h in SIGNED_HEADERS)
    fields = [
        (b"v", b"1"),
        (b"a", label),
        (b"c", b"relaxed/relaxed"),
        (b"d", domain.encode()),
        (b"s", selector.encode()),
        (b"h", b" : ".join(headers)),
        (b"bh", base64.b64encode(body_hash)),
        (b"b", b""),
    ]
    value = signer.gen_header(fields, headers, policy, b"DKIM-Signature", key)
    return b"DKIM-Signature: " + value + raw


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
    """Serve the test keys under their selectors, for any domain."""
    if name.startswith(f"{SELECTOR}._domainkey.".encode()):
        return public_record()
    if name.startswith(f"{ED25519_SELECTOR}._domainkey.".encode()):
        return ed25519_record()
    return None
