#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID

logger = logging.getLogger(__name__)


@dataclass
class CertificateAttributes:
    common_name: Optional[str] = None
    email_address: Optional[str] = None
    organization_name: Optional[str] = None
    country_name: Optional[str] = None
    state_or_province_name: Optional[str] = None
    locality_name: Optional[str] = None
    is_ca: Optional[bool] = False


class Certificate:
    def __init__(self, certificate_str: str):
        """Initialize the Certificate class.

        Args:
          certificate_str (str): The certificate in PEM format.
        """
        self.certificate_str = certificate_str
        self.certificate = x509.load_pem_x509_certificate(self.certificate_str.encode("utf-8"))

    @property
    def common_name(self) -> Optional[str]:
        try:
            common_name = self.certificate.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
        except IndexError:
            return None
        return str(common_name)

    @property
    def organization_name(self) -> Optional[str]:
        try:
            org = self.certificate.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[
                0
            ].value
        except IndexError:
            return None
        return str(org)

    @property
    def email_address(self) -> Optional[str]:
        try:
            email = self.certificate.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[
                0
            ].value
        except IndexError:
            return None
        return str(email)

    @property
    def country_name(self) -> Optional[str]:
        try:
            country = self.certificate.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[
                0
            ].value
        except IndexError:
            return None
        return str(country)

    @property
    def state_or_province_name(self) -> Optional[str]:
        try:
            state = self.certificate.subject.get_attributes_for_oid(
                x509.NameOID.STATE_OR_PROVINCE_NAME
            )[0].value
        except IndexError:
            return None
        return str(state)

    @property
    def locality_name(self) -> Optional[str]:
        try:
            locality = self.certificate.subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[
                0
            ].value
        except IndexError:
            return None
        return str(locality)

    @property
    def is_ca(self) -> bool:
        try:
            is_ca = self.certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value.ca  # type: ignore[reportAttributeAccessIssue]
            return is_ca
        except x509.ExtensionNotFound:
            return False

    def has_attributes(
        self,
        certificate_attributes: CertificateAttributes,
    ) -> bool:
        """Return True if the certificate has the expected attributes."""
        if self.common_name != certificate_attributes.common_name:
            logger.info(
                "Common name does not match: %s != %s",
                self.common_name,
                certificate_attributes.common_name,
            )
            return False
        if self.organization_name != certificate_attributes.organization_name:
            logger.info(
                "Organization name does not match: %s != %s",
                self.organization_name,
                certificate_attributes.organization_name,
            )
            return False
        if self.country_name != certificate_attributes.country_name:
            logger.info(
                "Country name does not match: %s != %s",
                self.country_name,
                certificate_attributes.country_name,
            )
            return False
        if self.state_or_province_name != certificate_attributes.state_or_province_name:
            logger.info(
                "State or province name does not match: %s != %s",
                self.state_or_province_name,
                certificate_attributes.state_or_province_name,
            )
            return False
        if self.locality_name != certificate_attributes.locality_name:
            logger.info(
                "Locality name does not match: %s != %s",
                self.locality_name,
                certificate_attributes.locality_name,
            )
            return False
        if self.email_address != certificate_attributes.email_address:
            logger.info(
                "Email address does not match: %s != %s",
                self.email_address,
                certificate_attributes.email_address,
            )
            return False
        if self.is_ca != certificate_attributes.is_ca:
            logger.info(
                "Is CA does not match: %s != %s",
                self.is_ca,
                certificate_attributes.is_ca,
            )
            return False
        return True
