#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from typing import List, Optional

from cryptography import x509

logger = logging.getLogger(__name__)


class Certificate:
    def __init__(self, certificate_str: str):
        """Initialize the Certificate class.

        Args:
          certificate_str (str): The certificate in PEM format.
        """
        self.certificate_str = certificate_str
        self.certificate = x509.load_pem_x509_certificate(self.certificate_str.encode("utf-8"))

    @property
    def subject(self) -> Optional[str]:
        return self.certificate.subject.rfc4514_string()

    @property
    def sans_dns(self) -> List[str]:
        try:
            sans = self.certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            return []
        return [str(san) for san in sans]

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

    def has_attributes(
        self,
        sans_dns: list[str],
        email_address: Optional[str] = None,
        organization_name: Optional[str] = None,
        country_name: Optional[str] = None,
        state_or_province_name: Optional[str] = None,
        locality_name: Optional[str] = None,
    ) -> bool:
        """Return True if the certificate has the expected attributes."""
        if self.organization_name != organization_name:
            logger.info(
                "Organization name does not match: %s != %s",
                self.organization_name,
                organization_name,
            )
            return False
        if self.country_name != country_name:
            logger.info("Country name does not match: %s != %s", self.country_name, country_name)
            return False
        if self.state_or_province_name != state_or_province_name:
            logger.info(
                "State or province name does not match: %s != %s",
                self.state_or_province_name,
                state_or_province_name,
            )
            return False
        if self.locality_name != locality_name:
            logger.info(
                "Locality name does not match: %s != %s", self.locality_name, locality_name
            )
            return False
        if self.email_address != email_address:
            logger.info(
                "Email address does not match: %s != %s", self.email_address, email_address
            )
            return False
        if sorted(self.sans_dns) != sorted(sans_dns):
            logger.info("SANs do not match: %s != %s", self.sans_dns, sans_dns)
            return False
        return True
