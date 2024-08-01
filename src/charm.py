#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm that requests X.509 certificates using the tls-certificates interface."""

import logging
from typing import List, Optional, Tuple, cast

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequest,
    Mode,
    TLSCertificatesRequiresV4,
)
from ops.charm import ActionEvent, CharmBase, CollectStatusEvent, RelationBrokenEvent
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, SecretNotFoundError, StatusBase

logger = logging.getLogger(__name__)


class TLSRequirerCharm(CharmBase):
    """TLS Requirer Charm."""

    def __init__(self, *args):
        """Handle events for certificate management."""
        super().__init__(*args)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.on.certificates_relation_joined, self._configure)
        self.framework.observe(self.on.certificates_relation_changed, self._configure)
        self.framework.observe(
            self.on.certificates_relation_broken,
            self._on_certificates_relation_broken,
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)
        mode = self._get_config_mode()
        if not mode:
            logger.error("Invalid mode configuration: only 'unit' and 'app' are allowed")
            return
        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name="certificates",
            certificate_requests=self._get_certificate_requests(),
            mode=mode,
            refresh_events=[
                self.on.config_changed,
            ],
        )

    @property
    def _certificates_relation_created(self) -> bool:
        """Return whether the `certificates` relation was created."""
        return self._relation_created("certificates")

    def _relation_created(self, relation_name: str) -> bool:
        """Return whether given relation was created."""
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
        if mode == Mode.UNIT:
            status = self._collect_status_unit_mode()
            event.add_status(status)
            return
        elif mode == Mode.APP:
            status = self._collect_status_app_mode()
            event.add_status(status)
            return

    def _collect_status_unit_mode(self) -> StatusBase:
        """Collect status for the unit mode."""
        if not self._certificates_relation_created:
            return ActiveStatus("Waiting for certificates relation")
        if not self._unit_certificate_is_stored():
            return ActiveStatus("Waiting for unit certificate")
        return ActiveStatus("Unit certificate is available")

    def _collect_status_app_mode(self) -> StatusBase:
        """Collect status for the app mode."""
        if not self.unit.is_leader():
            return BlockedStatus("This charm can't scale when deployed in app mode")
        if not self._certificates_relation_created:
            return ActiveStatus("Waiting for certificates relation")
        if not self._app_certificate_is_stored():
            return ActiveStatus("Waiting for app certificate")
        return ActiveStatus("App certificate is available")

    def _configure(self, event: EventBase) -> None:
        """Manage certificate lifecycle."""
        mode = self._get_config_mode()
        if not self._mode_config_is_valid():
            logger.error("Invalid mode configuration: only 'unit' and 'app' are allowed")
            return
        if mode == Mode.UNIT:
            self._configure_unit_mode()
        elif mode == Mode.APP:
            self._configure_app_mode()

    def _configure_unit_mode(self):
        """Manage certificate lifecycle when they are managed per unit."""
        if not self._certificates_relation_created:
            return
        if not self._unit_certificate_is_stored():
            self._store_unit_certificate()

    def _configure_app_mode(self):
        """Manage certificate lifecycle when they are managed per application."""
        if not self.unit.is_leader():
            return
        if not self._certificates_relation_created:
            return
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

    def _get_certificate_requests(self) -> List[CertificateRequest]:
        return [
            CertificateRequest(
                common_name=self._get_common_name(),
                sans_dns=self._get_config_sans_dns(),
                organization=self._get_config_organization_name(),
                email_address=self._get_config_email_address(),
                country_name=self._get_config_country_name(),
                state_or_province_name=self._get_config_state_or_province_name(),
                locality_name=self._get_config_locality_name(),
            )
        ]

    def _unit_certificate_is_stored(self) -> bool:
        """Return whether unit certificate is available in Juju secret."""
        if not self._unit_certificate_secret_exists:
            return False
        stored_certificate_secret = self.model.get_secret(
            label=self._get_unit_certificate_secret_label()
        )
        stored_certificate = stored_certificate_secret.get_content(refresh=True)["certificate"]
        assigned_certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_requests()[0]
        )
        if not assigned_certificate:
            return False
        return str(assigned_certificate.certificate) == stored_certificate

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
        assigned_certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_requests()[0]
        )
        if not assigned_certificate:
            return False
        return str(assigned_certificate.certificate) == stored_certificate

    def _store_unit_certificate(self) -> None:
        """Store the assigned unit certificate in a Juju secret."""
        assigned_certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_requests()[0]
        )
        if not assigned_certificate:
            logger.info("No unit certificate is assigned")
            return
        certificate_secret_content = {
            "certificate": str(assigned_certificate.certificate),
            "ca-certificate": str(assigned_certificate.ca),
            "csr": str(assigned_certificate.certificate_signing_request),
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
            logger.info(
                "New unit certificate is stored: %s", str(assigned_certificate.certificate)
            )
            return
        certificate_secret.set_content(content=certificate_secret_content)
        logger.info("Unit certificate is updated: %s", str(assigned_certificate.certificate))

    def _store_app_certificate(self) -> None:
        """Store the assigned app certificate in a Juju secret."""
        if not self.unit.is_leader():
            return
        assigned_certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_requests()[0]
        )
        if not assigned_certificate:
            logger.info("No app certificate is assigned")
            return
        certificate_secret_content = {
            "certificate": str(assigned_certificate.certificate),
            "ca-certificate": str(assigned_certificate.ca),
            "csr": str(assigned_certificate.certificate_signing_request),
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
            logger.info("New app certificate is stored: %s", str(assigned_certificate.certificate))
            return
        certificate_secret.set_content(content=certificate_secret_content)
        logger.info("App certificate is updated: %s", str(assigned_certificate.certificate))

    def _get_common_name(self) -> str:
        """Return common name.

        If `common_name` config option is set, it will be used as a common name.
        Otherwise, the common name will be generated based on the application name and unit number.
        """
        config_common_name = cast(str, self.model.config.get("common_name"))
        if config_common_name:
            return config_common_name
        mode = self._get_config_mode()
        if mode == Mode.UNIT:
            return f"{self.app.name}-{self._get_unit_number()}.{self.model.name}"
        elif mode == Mode.APP:
            return f"{self.app.name}.{self.model.name}"
        raise ValueError("Invalid mode, only 'unit' and 'app' are allowed.")

    def _mode_config_is_valid(self) -> bool:
        """Return whether mode configuration is valid."""
        config_mode = self._get_config_mode()
        if config_mode not in [Mode.UNIT, Mode.APP]:
            return False
        return True

    def _get_config_mode(self) -> Optional[Mode]:
        """Return mode from the configuration."""
        modes = {
            "unit": Mode.UNIT,
            "app": Mode.APP,
        }
        mode = self.model.config.get("mode")
        if not mode or not isinstance(mode, str):
            return None
        return modes.get(mode, None)

    def _get_config_sans_dns(self) -> Tuple[str, ...]:
        """Return DNS Subject Alternative Names from the configuration.

        If `sans_dns` config option is set, it will be used as a list of DNS
        Subject Alternative Names. Otherwise, the list will contain a single
        DNS Subject Alternative Name based on the application name and unit number.
        """
        config_sans_dns = self.model.config.get("sans_dns", "")
        if config_sans_dns and isinstance(config_sans_dns, str):
            return tuple(config_sans_dns.split(","))
        mode = self._get_config_mode()
        if mode == Mode.UNIT:
            return (f"{self.app.name}-{self._get_unit_number()}.{self.model.name}",)
        elif mode == Mode.APP:
            return (f"{self.app.name}.{self.model.name}",)
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
        """Return value of specified string juju config."""
        value = self.model.config.get(key, None)
        if not value or not isinstance(value, str):
            return None
        return value

    @property
    def _unit_certificate_secret_exists(self) -> bool:
        return self._secret_exists(label=self._get_unit_certificate_secret_label())

    @property
    def _app_certificate_secret_exists(self) -> bool:
        return self._secret_exists(label=self._get_app_certificate_secret_label())

    def _secret_exists(self, label: str) -> bool:
        """Return whether a given secret exists."""
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
        if mode == Mode.UNIT:
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
        elif mode == Mode.APP:
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

    def _get_unit_certificate_secret_label(self) -> str:
        return f"certificate-{self._get_unit_number()}"

    def _get_app_certificate_secret_label(self) -> str:
        return "certificate"


if __name__ == "__main__":
    main(TLSRequirerCharm)
