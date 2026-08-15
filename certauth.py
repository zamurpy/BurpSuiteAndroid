# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB
# (c) 2026 ZamurSec - All Rights Reserved. See LICENSE. Do not redistribute/modify without permission.

"""
certauth.py - Root CA + on-the-fly leaf certificate generation
Dipakai buat MITM HTTPS (sama seperti cara kerja Burp Suite / mitmproxy).

Root CA HARUS diinstall manual di device/browser target supaya HTTPS
tidak muncul warning "certificate not trusted". Ini standar untuk semua
proxy interception tool -- hanya lakukan pada perangkat/traffic milikmu
sendiri atau yang punya izin eksplisit untuk diuji.
"""
import os
import datetime
import threading

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca")
CA_KEY_PATH = os.path.join(BASE_DIR, "eh_burp_ca.key")
CA_CERT_PATH = os.path.join(BASE_DIR, "eh_burp_ca.pem")
LEAF_DIR = os.path.join(BASE_DIR, "leaf")

_lock = threading.Lock()
_leaf_cache = {}


def _ensure_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(LEAF_DIR, exist_ok=True)


def ensure_root_ca():
    """Generate root CA sekali saja kalau belum ada."""
    if not HAVE_CRYPTO:
        return None, None
    _ensure_dirs()
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        return CA_KEY_PATH, CA_CERT_PATH

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Ethical Hacking Burp CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EthicalHackingBurp"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return CA_KEY_PATH, CA_CERT_PATH


def get_cert_for_host(host):
    """Return (certfile, keyfile) path untuk host tertentu, signed by our CA."""
    if not HAVE_CRYPTO:
        return None, None
    with _lock:
        if host in _leaf_cache:
            return _leaf_cache[host]

        ca_key_path, ca_cert_path = ensure_root_ca()
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        san = x509.SubjectAlternativeName([x509.DNSName(host)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
            .add_extension(san, critical=False)
            .sign(ca_key, hashes.SHA256())
        )

        cert_path = os.path.join(LEAF_DIR, f"{host}.pem")
        key_path = os.path.join(LEAF_DIR, f"{host}.key")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        _leaf_cache[host] = (cert_path, key_path)
        return cert_path, key_path
