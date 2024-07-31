# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from datetime import datetime, timedelta, timezone
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_private_key() -> str:
    """Generate a private key of size 2048."""
    key_size = 2048
    public_exponent = 65537
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_bytes.decode().strip()


def generate_csr(
    private_key: str,
    common_name: str,
    organization_name: str,
    email_address: str,
    country_name: str,
    state_or_province_name: str,
    locality_name: str,
    sans_dns: List[str],
) -> str:
    """Generate a CSR using private key and subject."""
    signing_key = serialization.load_pem_private_key(private_key.encode(), password=None)
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
    return signed_certificate.public_bytes(serialization.Encoding.PEM).decode().strip()


def generate_ca(
    private_key: str,
    common_name: str,
    validity: int = 365,
) -> str:
    """Generate a CA Certificate.

    Args:
        private_key (bytes): Private key
        private_key_password (bytes): Private key password
        common_name (str): Certificate common name.
        validity (int): Certificate validity time (in days)
        country (str): Certificate Issuing country

    Returns:
        str: CA Certificate
    """
    private_key_object = serialization.load_pem_private_key(private_key.encode(), password=None)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        ]
    )
    subject_identifier_object = x509.SubjectKeyIdentifier.from_public_key(
        private_key_object.public_key()  # type: ignore[arg-type]
    )
    subject_identifier = key_identifier = subject_identifier_object.public_bytes()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key_object.public_key())  # type: ignore[arg-type]
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity))
        .add_extension(x509.SubjectKeyIdentifier(digest=subject_identifier), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key_object, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()


def generate_certificate(
    csr: str,
    ca: str,
    ca_key: str,
    validity: int = 24 * 365,
) -> str:
    """Generate a TLS certificate based on a CSR.

    Args:
        csr (str): CSR
        ca (str): CA Certificate
        ca_key (str): CA private key
        validity (int): Certificate validity (in hours)

    Returns:
        str: Certificate
    """
    csr_object = x509.load_pem_x509_csr(csr.encode())
    csr_subject = csr_object.subject
    csr_common_name = csr_subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    issuer = x509.load_pem_x509_certificate(ca.encode()).issuer
    private_key = serialization.load_pem_private_key(ca_key.encode(), password=None)
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, csr_common_name),
        ]
    )

    if validity > 0:
        not_valid_before = datetime.now(timezone.utc)
        not_valid_after = datetime.now(timezone.utc) + timedelta(hours=validity)
    else:
        not_valid_before = datetime.now(timezone.utc) + timedelta(hours=validity)
        not_valid_after = datetime.now(timezone.utc) - timedelta(seconds=1)
    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(csr_object.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )

    certificate_builder._version = x509.Version.v3
    cert = certificate_builder.sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
    return cert.public_bytes(serialization.Encoding.PEM).decode().strip()
