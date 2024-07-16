#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm that requests X.509 certificates using the tls-certificates interface."""

import logging
import secrets
from typing import List, Optional, cast

from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
    TLSCertificatesRequiresV3,
    generate_csr,
    generate_private_key,
)
from cryptography import x509
from cryptography.x509.oid import NameOID
from ops.charm import ActionEvent, CharmBase, CollectStatusEvent, RelationBrokenEvent
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, SecretNotFoundError, StatusBase, WaitingStatus

logger = logging.getLogger(__name__)


def csr_has_attributes(  # noqa: C901
    csr: str,
    common_name: str,
    sans_dns: List[str],
    organization: Optional[str],
    email_address: Optional[str],
    country_name: Optional[str],
    state_or_province_name: Optional[str],
    locality_name: Optional[str],
) -> bool:
    """Check whether CSR has the specified attributes."""
    csr_object = x509.load_pem_x509_csr(csr.encode())
    csr_common_name = csr_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    csr_country_name = csr_object.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    csr_state_or_province_name = csr_object.subject.get_attributes_for_oid(
        NameOID.STATE_OR_PROVINCE_NAME
    )
    csr_locality_name = csr_object.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
    csr_organization_name = csr_object.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    csr_email_address = csr_object.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    if len(csr_common_name) == 0 and common_name:
        return False
    if csr_common_name[0].value != common_name:
        return False
    if len(csr_country_name) == 0 and country_name:
        return False
    if len(csr_country_name) != 0 and csr_country_name[0].value != country_name:
        return False
    if len(csr_state_or_province_name) == 0 and state_or_province_name:
        return False
    if (
        len(csr_state_or_province_name) != 0
        and csr_state_or_province_name[0].value != state_or_province_name
    ):
        return False
    if len(csr_locality_name) == 0 and locality_name:
        return False
    if len(csr_locality_name) != 0 and csr_locality_name[0].value != locality_name:
        return False
    if len(csr_organization_name) == 0 and organization:
        return False
    if len(csr_organization_name) != 0 and csr_organization_name[0].value != organization:
        return False
    if len(csr_email_address) == 0 and email_address:
        return False
    if len(csr_email_address) != 0 and csr_email_address[0].value != email_address:
        return False
    sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if sorted([str(san.value) for san in sans]) != sorted(sans_dns):
        return False
    return True


class TLSRequirerCharm(CharmBase):
    """TLS Requirer Charm."""

    def __init__(self, *args):
        """Handle events for certificate management."""
        super().__init__(*args)
        self.certificates = TLSCertificatesRequiresV3(self, "certificates")
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.on.certificates_relation_joined, self._configure)
        self.framework.observe(
            self.on.certificates_relation_broken,
            self._on_certificates_relation_broken,
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)
        self.framework.observe(self.certificates.on.certificate_available, self._configure)

    @property
    def _certificates_relation_created(self) -> bool:
        """Return whether the `certificates` relation was created.

        Returns:
            bool: Whether the `certificates` relation was created.
        """
        return self._relation_created("certificates")

    def _relation_created(self, relation_name: str) -> bool:
        """Return whether given relation was created.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: Whether a given relation was created.
        """
        try:
            return bool(self.model.get_relation(relation_name))
        except KeyError:
            return False

    def _on_collect_status(self, event: CollectStatusEvent) -> None:
        """Collect status for the charm."""
        if not self._mode_config_is_valid():
            event.add_status(
                BlockedStatus("Invalid mode configuration: only 'unit' and 'app' are allowed")
            )
            return
        mode = self._get_config_mode()
        if mode == "unit":
            status = self._collect_status_unit_mode()
            event.add_status(status)
            return
        elif mode == "app":
            status = self._collect_status_app_mode()
            event.add_status(status)
            return

    def _collect_status_unit_mode(self) -> StatusBase:
        """Collect status for the unit mode."""
        if not self._unit_private_key_is_stored:
            return WaitingStatus("Waiting for unit private key to be generated")
        if not self._unit_csr_secret_exists:
            return WaitingStatus("Waiting for unit CSR to be generated")
        if not self._certificates_relation_created:
            return ActiveStatus()
        if not self._unit_certificate_is_requested():
            return ActiveStatus("Certificate relation is created")
        if not self._unit_certificate_is_stored():
            return ActiveStatus("Unit certificate request is sent")
        return ActiveStatus("Unit certificate is available")

    def _collect_status_app_mode(self) -> StatusBase:
        """Collect status for the app mode."""
        if not self._app_private_key_is_stored:
            return WaitingStatus("Waiting for app private key to be generated")
        if not self._app_csr_secret_exists:
            return WaitingStatus("Waiting for app CSR to be generated")
        if not self._certificates_relation_created:
            return ActiveStatus()
        if not self._app_certificate_is_requested():
            return ActiveStatus("Certificate relation is created")
        if not self._app_certificate_is_stored():
            return ActiveStatus("App certificate request is sent")
        return ActiveStatus("App certificate is available")

    def _configure(self, event: EventBase) -> None:
        """Manage certificate lifecycle."""
        mode = self._get_config_mode()
        if not self._mode_config_is_valid():
            logger.error("Invalid mode configuration: only 'unit' and 'app' are allowed")
            return
        if mode == "unit":
            self._configure_unit_mode()
        elif mode == "app":
            self._configure_app_mode()

    def _configure_unit_mode(self):
        """Manage certificate lifecycle when they are managed per unit."""
        if not self._unit_private_key_is_stored:
            self._generate_unit_private_key()
        if not self._unit_csr_secret_exists or not self._unit_csr_has_attributes(
            common_name=self._get_common_name(),
            sans_dns=self._get_config_sans_dns(),
            organization=self._get_config_organization_name(),
            email_address=self._get_config_email_address(),
            country_name=self._get_config_country_name(),
            state_or_province_name=self._get_config_state_or_province_name(),
            locality_name=self._get_config_locality_name(),
        ):
            self._generate_unit_csr(
                common_name=self._get_common_name(),
                sans_dns=self._get_config_sans_dns(),
                organization=self._get_config_organization_name(),
                email_address=self._get_config_email_address(),
                country_name=self._get_config_country_name(),
                state_or_province_name=self._get_config_state_or_province_name(),
                locality_name=self._get_config_locality_name(),
            )
        if not self._certificates_relation_created:
            return
        if not self._unit_certificate_is_requested():
            self._request_unit_certificate()
        if not self._unit_certificate_is_stored():
            self._store_unit_certificate()

    def _configure_app_mode(self):
        """Manage certificate lifecycle when they are managed per application."""
        if not self.unit.is_leader():
            return
        if not self._app_private_key_is_stored:
            self._generate_app_private_key()
        if not self._app_csr_secret_exists or not self._app_csr_has_attributes(
            common_name=self._get_common_name(),
            sans_dns=self._get_config_sans_dns(),
            organization=self._get_config_organization_name(),
            email_address=self._get_config_email_address(),
            country_name=self._get_config_country_name(),
            state_or_province_name=self._get_config_state_or_province_name(),
            locality_name=self._get_config_locality_name(),
        ):
            self._generate_app_csr(
                common_name=self._get_common_name(),
                sans_dns=self._get_config_sans_dns(),
                organization=self._get_config_organization_name(),
                email_address=self._get_config_email_address(),
                country_name=self._get_config_country_name(),
                state_or_province_name=self._get_config_state_or_province_name(),
                locality_name=self._get_config_locality_name(),
            )
        if not self._certificates_relation_created:
            return
        if not self._app_certificate_is_requested():
            self._request_app_certificate()
        if not self._app_certificate_is_stored():
            self._store_app_certificate()

    def _on_certificates_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Remove Certificate from juju secret.

        Args:
            event: Juju event.
        """
        if self._unit_certificate_secret_exists:
            certificate_secret = self.model.get_secret(
                label=self._get_unit_certificate_secret_label()
            )
            certificate_secret.remove_all_revisions()
        if self._app_certificate_secret_exists:
            if not self.unit.is_leader():
                return
            certificate_secret = self.model.get_secret(
                label=self._get_app_certificate_secret_label()
            )
            certificate_secret.remove_all_revisions()

    def _unit_certificate_is_stored(self) -> bool:
        """Return whether unit certificate is available in Juju secret."""
        if not self._unit_certificate_secret_exists:
            return False
        stored_certificate_secret = self.model.get_secret(
            label=self._get_unit_certificate_secret_label()
        )
        stored_certificate = stored_certificate_secret.get_content(refresh=True)["certificate"]

        assigned_certificate = self._get_assigned_unit_certificate()
        if not assigned_certificate:
            return False
        return assigned_certificate.certificate.strip() == stored_certificate.strip()

    def _app_certificate_is_stored(self) -> bool:
        """Return whether app certificate is available in Juju secret."""
        if not self.unit.is_leader():
            return False
        if not self._app_certificate_secret_exists:
            return False
        stored_certificate_secret = self.model.get_secret(
            label=self._get_app_certificate_secret_label()
        )
        stored_certificate = stored_certificate_secret.get_content(refresh=True)["certificate"]
        assigned_certificate = self._get_assigned_app_certificate()
        if not assigned_certificate:
            return False
        return assigned_certificate.certificate.strip() == stored_certificate.strip()

    def _get_assigned_unit_certificate(self) -> Optional[ProviderCertificate]:
        csr_secret = self.model.get_secret(label=self._get_unit_csr_secret_label())
        csr_secret_content = csr_secret.get_content(refresh=True)
        provider_certificates = self.certificates.get_assigned_certificates()
        for certificate in provider_certificates:
            if certificate.csr.strip() == csr_secret_content["csr"].strip():
                return certificate
        return None

    def _get_assigned_app_certificate(self) -> Optional[ProviderCertificate]:
        csr_secret = self.model.get_secret(label=self._get_app_csr_secret_label())
        csr_secret_content = csr_secret.get_content(refresh=True)
        provider_certificates = self.certificates.get_assigned_certificates()
        for certificate in provider_certificates:
            if certificate.csr.strip() == csr_secret_content["csr"].strip():
                return certificate
        return None

    def _store_unit_certificate(self) -> None:
        """Store the assigned unit certificate in a Juju secret."""
        assigned_certificate = self._get_assigned_unit_certificate()
        if not assigned_certificate:
            logger.info("No unit certificate is assigned")
            return
        certificate_secret_content = {
            "certificate": assigned_certificate.certificate,
            "ca-certificate": assigned_certificate.ca,
            "csr": assigned_certificate.csr,
        }
        try:
            certificate_secret = self.model.get_secret(
                label=self._get_unit_certificate_secret_label()
            )
        except SecretNotFoundError:
            self.unit.add_secret(
                content=certificate_secret_content,
                label=self._get_unit_certificate_secret_label(),
            )
            logger.info("New unit certificate is stored: %s", assigned_certificate.certificate)
            return
        certificate_secret.set_content(content=certificate_secret_content)
        logger.info("Unit certificate is updated: %s", assigned_certificate.certificate)

    def _store_app_certificate(self) -> None:
        """Store the assigned app certificate in a Juju secret."""
        if not self.unit.is_leader():
            return
        assigned_certificate = self._get_assigned_app_certificate()
        if not assigned_certificate:
            logger.info("No app certificate is assigned")
            return
        certificate_secret_content = {
            "certificate": assigned_certificate.certificate,
            "ca-certificate": assigned_certificate.ca,
            "csr": assigned_certificate.csr,
        }
        try:
            certificate_secret = self.model.get_secret(
                label=self._get_app_certificate_secret_label()
            )
        except SecretNotFoundError:
            self.app.add_secret(
                content=certificate_secret_content,
                label=self._get_app_certificate_secret_label(),
            )
            logger.info("New app certificate is stored: %s", assigned_certificate.certificate)
            return
        certificate_secret.set_content(content=certificate_secret_content)
        logger.info("App certificate is updated: %s", assigned_certificate.certificate)

    def _generate_unit_private_key(self):
        """Generate private key and store it in Juju secret."""
        private_key_password = generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        self.unit.add_secret(
            content={
                "private-key-password": private_key_password,
                "private-key": private_key.decode(),
            },
            label=self._get_unit_private_key_secret_label(),
        )
        logger.info("Unit private key generated")

    def _generate_app_private_key(self):
        """Generate private key and store it in Juju secret."""
        private_key_password = generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        self.app.add_secret(
            content={
                "private-key-password": private_key_password,
                "private-key": private_key.decode(),
            },
            label=self._get_app_private_key_secret_label(),
        )
        logger.info("App private key generated")

    def _get_common_name(self) -> str:
        """Return common name.

        If `common_name` config option is set, it will be used as a common name.
        Otherwise, the common name will be generated based on the application name and unit number.
        """
        config_common_name = cast(str, self.model.config.get("common_name"))
        if config_common_name:
            return config_common_name
        mode = self._get_config_mode()
        if mode == "unit":
            return f"{self.app.name}-{self._get_unit_number()}.{self.model.name}"
        elif mode == "app":
            return f"{self.app.name}.{self.model.name}"
        raise ValueError("Invalid mode, only 'unit' and 'app' are allowed.")

    def _mode_config_is_valid(self) -> bool:
        """Return whether mode configuration is valid."""
        config_mode = self._get_config_mode()
        if config_mode not in ["unit", "app"]:
            return False
        return True

    def _get_config_mode(self) -> str:
        """Return mode from the configuration."""
        mode = self.model.config.get("mode")
        if not mode or not isinstance(mode, str):
            return "unit"
        return mode

    def _get_config_sans_dns(self) -> List[str]:
        """Return DNS Subject Alternative Names from the configuration.

        If `sans_dns` config option is set, it will be used as a list of DNS
        Subject Alternative Names. Otherwise, the list will contain a single
        DNS Subject Alternative Name based on the application name and unit number.
        """
        config_sans_dns = self.model.config.get("sans_dns", "")
        if config_sans_dns and isinstance(config_sans_dns, str):
            return config_sans_dns.split(",")
        mode = self._get_config_mode()
        if mode == "unit":
            return [f"{self.app.name}-{self._get_unit_number()}.{self.model.name}"]
        elif mode == "app":
            return [f"{self.app.name}.{self.model.name}"]
        raise ValueError("Invalid mode, only 'unit' and 'app' are allowed.")

    def _get_config_organization_name(self) -> Optional[str]:
        """Return organization name from the configuration."""
        return self._get_str_config("organization_name")

    def _get_config_email_address(self) -> Optional[str]:
        """Return email address from the configuration."""
        return self._get_str_config("email_address")

    def _get_config_country_name(self) -> Optional[str]:
        """Return country name from the configuration."""
        return self._get_str_config("country_name")

    def _get_config_state_or_province_name(self) -> Optional[str]:
        """Return state or province name from the configuration."""
        return self._get_str_config("state_or_province_name")

    def _get_config_locality_name(self) -> Optional[str]:
        """Return locality name from the configuration."""
        return self._get_str_config("locality_name")

    def _get_str_config(self, key: str) -> Optional[str]:
        """Return value of specified string juju config.

        Checks type and makes sure to return a string or a None

        Args:
            key: config option key
        Returns:
            Value of the config or None
        """
        value = self.model.config.get(key, None)
        if not value or not isinstance(value, str):
            return None
        return value

    def _request_unit_certificate(self) -> None:
        """Request X.509 certificate for unit.

        Retrieves unit private key and password from Juju secret, generates a certificate
        signing request (CSR) and inserts it into the `certificates` relation unit relation data.
        """
        if not self._unit_csr_secret_exists:
            raise RuntimeError("Unit CSR is not stored")
        csr_secret = self.model.get_secret(label=self._get_unit_csr_secret_label())
        csr_secret_content = csr_secret.get_content(refresh=True)
        self.certificates.request_certificate_creation(
            certificate_signing_request=csr_secret_content["csr"].encode()
        )
        logger.info("Unit certificate request sent")

    def _request_app_certificate(self) -> None:
        """Request X.509 certificate for app.

        Retrieves app private key and password from Juju secret, generates a certificate
        signing request (CSR) and inserts it into the `certificates` relation app relation data.
        """
        if not self._app_csr_secret_exists:
            raise RuntimeError("App CSR is not stored")
        csr_secret = self.model.get_secret(label=self._get_app_csr_secret_label())
        csr_secret_content = csr_secret.get_content(refresh=True)
        self.certificates.request_certificate_creation(
            certificate_signing_request=csr_secret_content["csr"].encode()
        )
        logger.info("App certificate request sent")

    def _generate_unit_csr(
        self,
        common_name: str,
        sans_dns: List[str],
        organization: Optional[str],
        email_address: Optional[str],
        country_name: Optional[str],
        state_or_province_name: Optional[str],
        locality_name: Optional[str],
    ) -> None:
        """Generate unit CSR based on private key and stores it in Juju secret."""
        if not self._unit_private_key_is_stored:
            raise RuntimeError("Private key not stored.")
        private_key_secret = self.model.get_secret(label=self._get_unit_private_key_secret_label())
        private_key_secret_content = private_key_secret.get_content(refresh=True)
        csr = generate_csr(
            private_key=private_key_secret_content["private-key"].encode(),
            private_key_password=private_key_secret_content["private-key-password"].encode(),
            subject=common_name,
            sans_dns=sans_dns,
            organization=organization,
            email_address=email_address,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
        )
        csr_secret_content = {"csr": csr.decode()}
        try:
            csr_secret = self.model.get_secret(label=self._get_unit_csr_secret_label())
        except SecretNotFoundError:
            self.unit.add_secret(
                content=csr_secret_content, label=self._get_unit_csr_secret_label()
            )
            logger.info("Unit CSR secret created")
            return
        csr_secret.set_content(content=csr_secret_content)
        logger.info("Unit CSR secret updated")

    def _generate_app_csr(
        self,
        common_name: str,
        sans_dns: List[str],
        organization: Optional[str],
        email_address: Optional[str],
        country_name: Optional[str],
        state_or_province_name: Optional[str],
        locality_name: Optional[str],
    ) -> None:
        """Generate app CSR based on private key and stores it in Juju secret."""
        if not self._app_private_key_is_stored:
            raise RuntimeError("Private key not stored.")
        private_key_secret = self.model.get_secret(label=self._get_app_private_key_secret_label())
        private_key_secret_content = private_key_secret.get_content(refresh=True)
        csr = generate_csr(
            private_key=private_key_secret_content["private-key"].encode(),
            private_key_password=private_key_secret_content["private-key-password"].encode(),
            subject=common_name,
            sans_dns=sans_dns,
            organization=organization,
            email_address=email_address,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
        )
        csr_secret_content = {"csr": csr.decode()}
        try:
            csr_secret = self.model.get_secret(label=self._get_app_csr_secret_label())
        except SecretNotFoundError:
            self.app.add_secret(content=csr_secret_content, label=self._get_app_csr_secret_label())
            logger.info("App CSR secret created")
            return
        csr_secret.set_content(content=csr_secret_content)
        logger.info("App CSR secret updated")

    def _unit_csr_has_attributes(
        self,
        common_name: str,
        sans_dns: List[str],
        organization: Optional[str],
        email_address: Optional[str],
        country_name: Optional[str],
        state_or_province_name: Optional[str],
        locality_name: Optional[str],
    ) -> bool:
        secret = self.model.get_secret(label=self._get_unit_csr_secret_label())
        content = secret.get_content(refresh=True)
        csr = content["csr"]
        return csr_has_attributes(
            csr=csr,
            common_name=common_name,
            sans_dns=sans_dns,
            organization=organization,
            email_address=email_address,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
        )

    def _app_csr_has_attributes(
        self,
        common_name: str,
        sans_dns: List[str],
        organization: Optional[str],
        email_address: Optional[str],
        country_name: Optional[str],
        state_or_province_name: Optional[str],
        locality_name: Optional[str],
    ) -> bool:
        secret = self.model.get_secret(label=self._get_app_csr_secret_label())
        content = secret.get_content(refresh=True)
        csr = content["csr"]
        return csr_has_attributes(
            csr=csr,
            common_name=common_name,
            sans_dns=sans_dns,
            organization=organization,
            email_address=email_address,
            country_name=country_name,
            state_or_province_name=state_or_province_name,
            locality_name=locality_name,
        )

    def _unit_certificate_is_requested(self) -> bool:
        """Return whether unit certificate request is made.

        Compare certificate requests in the TLS relation data
        with the CSR stored in the Juju secret.
        """
        if not self._unit_csr_secret_exists:
            raise RuntimeError("Unit CSR is not stored")
        stored_csr_secret = self.model.get_secret(label=self._get_unit_csr_secret_label())
        stored_csr = stored_csr_secret.get_content(refresh=True)["csr"]
        requested_csrs = self.certificates.get_certificate_signing_requests()
        for requested_csr in requested_csrs:
            if requested_csr.csr.strip() == stored_csr.strip():
                return True
        return False

    def _app_certificate_is_requested(self) -> bool:
        """Return whether app certificate request is made.

        Compare certificate requests in the TLS relation data
        with the CSR stored in the Juju secret.
        """
        if not self._app_csr_secret_exists:
            raise RuntimeError("App CSR is not stored")
        stored_csr_secret = self.model.get_secret(label=self._get_app_csr_secret_label())
        stored_csr = stored_csr_secret.get_content(refresh=True)["csr"]
        requested_csrs = self.certificates.get_certificate_signing_requests()
        for requested_csr in requested_csrs:
            if requested_csr.csr.strip() == stored_csr.strip():
                return True
        return False

    @property
    def _unit_private_key_is_stored(self) -> bool:
        return self._secret_exists(label=self._get_unit_private_key_secret_label())

    @property
    def _app_private_key_is_stored(self) -> bool:
        return self._secret_exists(label=self._get_app_private_key_secret_label())

    @property
    def _unit_csr_secret_exists(self) -> bool:
        return self._secret_exists(label=self._get_unit_csr_secret_label())

    @property
    def _app_csr_secret_exists(self) -> bool:
        return self._secret_exists(label=self._get_app_csr_secret_label())

    @property
    def _unit_certificate_secret_exists(self) -> bool:
        return self._secret_exists(label=self._get_unit_certificate_secret_label())

    @property
    def _app_certificate_secret_exists(self) -> bool:
        return self._secret_exists(label=self._get_app_certificate_secret_label())

    def _secret_exists(self, label: str) -> bool:
        """Return whether a given secret exists.

        Args:
            label: Juju secret label

        Returns:
            bool: Whether the secret exists
        """
        try:
            self.model.get_secret(label=label)
            return True
        except SecretNotFoundError:
            return False

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `get-certificate` Juju action.

        Args:
            event: Juju event
        """
        if not self._mode_config_is_valid():
            event.fail("Invalid mode configuration: only 'unit' and 'app' are allowed")
            return
        mode = self._get_config_mode()
        if mode == "unit":
            if self._unit_certificate_is_stored():
                secret = self.model.get_secret(label=self._get_unit_certificate_secret_label())
                content = secret.get_content(refresh=True)
                event.set_results(
                    {
                        "certificate": content["certificate"],
                        "ca-certificate": content["ca-certificate"],
                        "csr": content["csr"],
                    }
                )
            else:
                event.fail("Unit certificate not available")
        elif mode == "app":
            if self._app_certificate_is_stored():
                secret = self.model.get_secret(label=self._get_app_certificate_secret_label())
                content = secret.get_content(refresh=True)
                event.set_results(
                    {
                        "certificate": content["certificate"],
                        "ca-certificate": content["ca-certificate"],
                        "csr": content["csr"],
                    }
                )
            else:
                event.fail("App certificate not available")

    def _get_unit_number(self) -> str:
        return self.unit.name.split("/")[1]

    def _get_unit_private_key_secret_label(self) -> str:
        return f"private-key-{self._get_unit_number()}"

    def _get_app_private_key_secret_label(self) -> str:
        return "private-key"

    def _get_unit_csr_secret_label(self) -> str:
        return f"csr-{self._get_unit_number()}"

    def _get_app_csr_secret_label(self) -> str:
        return "csr"

    def _get_unit_certificate_secret_label(self) -> str:
        return f"certificate-{self._get_unit_number()}"

    def _get_app_certificate_secret_label(self) -> str:
        return "certificate"


def generate_password() -> str:
    """Generate a random string containing 64 bytes.

    Returns:
        str: Password
    """
    return secrets.token_hex(64)


if __name__ == "__main__":
    main(TLSRequirerCharm)
