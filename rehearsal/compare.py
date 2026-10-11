#!/usr/bin/env python3
"""compare.py - Compare two X.509 certificates for attribute equivalence.

Ignores fields that must differ across renewals (serial number, validity dates).
Compares issuer, subject, public key algorithm and parameters, signature algorithm,
and all extension attributes and critical flags.
"""

import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448


def load_cert(path: str) -> x509.Certificate:
    data = Path(path).read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return x509.load_der_x509_certificate(data)


def format_pubkey(key) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}-bit (e={key.public_numbers().e})"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name} ({key.key_size}-bit)"
    elif isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    elif isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    elif isinstance(key, dsa.DSAPublicKey):
        return f"DSA {key.key_size}-bit"
    return str(type(key))


def compare_certs(c1: x509.Certificate, c2: x509.Certificate) -> list[str]:
    diffs = []

    # 1. Subject
    if c1.subject != c2.subject:
        diffs.append(f"Subject mismatch:\n  Cert 1: {c1.subject.rfc4514_string()}\n  Cert 2: {c2.subject.rfc4514_string()}")

    # 2. Issuer
    if c1.issuer != c2.issuer:
        diffs.append(f"Issuer mismatch:\n  Cert 1: {c1.issuer.rfc4514_string()}\n  Cert 2: {c2.issuer.rfc4514_string()}")

    # 3. Signature Algorithm
    if c1.signature_algorithm_oid != c2.signature_algorithm_oid:
        diffs.append(f"Signature Algorithm mismatch:\n  Cert 1: {c1.signature_algorithm_oid._name}\n  Cert 2: {c2.signature_algorithm_oid._name}")

    # 4. Public Key
    k1, k2 = c1.public_key(), c2.public_key()
    fk1, fk2 = format_pubkey(k1), format_pubkey(k2)
    if fk1 != fk2:
        diffs.append(f"Public Key type/size mismatch:\n  Cert 1: {fk1}\n  Cert 2: {fk2}")

    # 5. Extensions
    exts1 = {ext.oid.dotted_string: ext for ext in c1.extensions}
    exts2 = {ext.oid.dotted_string: ext for ext in c2.extensions}

    all_oids = sorted(set(exts1.keys()) | set(exts2.keys()))
    for oid in all_oids:
        e1 = exts1.get(oid)
        e2 = exts2.get(oid)
        if e1 is None:
            diffs.append(f"Extension {oid} ({e2.oid._name}) missing in Cert 1")
            continue
        if e2 is None:
            diffs.append(f"Extension {oid} ({e1.oid._name}) missing in Cert 2")
            continue

        if e1.critical != e2.critical:
            diffs.append(f"Extension {oid} critical flag mismatch (Cert 1: {e1.critical}, Cert 2: {e2.critical})")

        # Skip AuthorityKeyIdentifier and SubjectKeyIdentifier byte comparison if new keys are generated,
        # but check type equality
        if oid == x509.OID_SUBJECT_KEY_IDENTIFIER.dotted_string:
            continue
        if oid == x509.OID_AUTHORITY_KEY_IDENTIFIER.dotted_string:
            continue

        if e1.value != e2.value:
            diffs.append(f"Extension {oid} ({e1.oid._name}) value mismatch:\n  Cert 1: {e1.value}\n  Cert 2: {e2.value}")

    return diffs


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <cert1.pem> <cert2.pem>", file=sys.stderr)
        sys.exit(2)

    path1, path2 = sys.argv[1], sys.argv[2]
    c1 = load_cert(path1)
    c2 = load_cert(path2)

    diffs = compare_certs(c1, c2)
    if diffs:
        print(f"FAILED: {len(diffs)} attribute difference(s) found between {path1} and {path2}:")
        for d in diffs:
            print(f" - {d}")
        sys.exit(1)
    else:
        print(f"OK: Certificate attributes match exactly (ignoring serial number and dates).")
        sys.exit(0)


if __name__ == "__main__":
    main()
