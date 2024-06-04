# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key(password: bytes) -> bytes:
    """Generate a private key of size 2048 with a user provided password."""
    key_size = 2048
    public_exponent = 65537
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    return key_bytes

def generate_csr(
    private_key: bytes,
    private_key_password: bytes,
    common_name: str,
    organization_name: str,
    email_address: str,
    country_name: str,
    state_or_province_name:str,
    locality_name: str,
    sans_dns: List[str],
) -> bytes:
    """Generate a CSR using private key and subject."""
    signing_key = serialization.load_pem_private_key(private_key, password=private_key_password)
    subject_name = [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    subject_name.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization_name))
    subject_name.append(x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email_address))
    subject_name.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country_name))
    subject_name.append(
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name)
    )
    subject_name.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality_name))
    csr = x509.CertificateSigningRequestBuilder(subject_name=x509.Name(subject_name))
    _sans: List[x509.GeneralName] = []
    _sans.extend([x509.DNSName(san) for san in sans_dns])
    if _sans:
        csr = csr.add_extension(x509.SubjectAlternativeName(set(_sans)), critical=False)
    signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
    return signed_certificate.public_bytes(serialization.Encoding.PEM)
