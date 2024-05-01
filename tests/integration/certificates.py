#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from typing import Optional

from cryptography import x509


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
    def organization_name(self) -> Optional[str]:
        try:
            org = self.certificate.subject.get_attributes_for_oid(
                x509.NameOID.ORGANIZATION_NAME
            )[0].value
        except IndexError:
            return None
        return str(org)

    @property
    def email_address(self) -> Optional[str]:
        try:
            email = self.certificate.subject.get_attributes_for_oid(
                x509.NameOID.EMAIL_ADDRESS
            )[0].value
        except IndexError:
            return None
        return str(email)

    @property
    def country_name(self) -> Optional[str]:
        try:
            country = self.certificate.subject.get_attributes_for_oid(
                x509.NameOID.COUNTRY_NAME
            )[0].value
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
            locality = self.certificate.subject.get_attributes_for_oid(
                x509.NameOID.LOCALITY_NAME
            )[0].value
        except IndexError:
            return None
        return str(locality)
