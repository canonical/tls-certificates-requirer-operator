#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm that requests X.509 certificates using the tls-certificates interface."""

import json
import logging
import secrets

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from ops.charm import ActionEvent, CharmBase, EventBase, InstallEvent, RelationBrokenEvent
from ops.main import main
from ops.model import ActiveStatus, SecretNotFoundError

logger = logging.getLogger(__name__)


class TLSRequirerOperatorCharm(CharmBase):
    """TLS Requirer Operator Charm."""

    def __init__(self, *args):
        """Handles events for certificate management."""
        super().__init__(*args)
        self.certificates = TLSCertificatesRequiresV2(self, "certificates")
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.on.certificates_relation_broken,
            self._on_certificates_relation_broken,
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )

    @property
    def _certificates_relation_created(self) -> bool:
        """Return whether the `certificates` relation was created.

        Returns:
            bool: Whether the `certificates` relation was created.
        """
        return self._relation_created("certificates")

    def _relation_created(self, relation_name: str) -> bool:
        """Returns whether given relation was created.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: Whether a given relation was created.
        """
        try:
            return bool(self.model.get_relation(relation_name))
        except KeyError:
            return False

    def _on_install(self, event: InstallEvent) -> None:
        """Generates password and private key and stores them in a Juju secret.

        Args:
            event: Juju event.
        """
        private_key_password = generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        self.unit.add_secret(
            content={
                "private-key-password": private_key_password,
                "private-key": private_key.decode(),
            },
            label=self._get_private_key_secret_label(),
        )
        logger.info("Private key generated")
        self.unit.status = ActiveStatus()

    def _on_certificates_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Removes Certificate from juju secret.

        Args:
            event: Juju event.
        """
        if self._certificate_is_stored:
            certificate_secret = self.model.get_secret(label=self._get_certificate_secret_label())
            certificate_secret.remove_all_revisions()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Stores the certificate in a Juju secret.

        Args:
            event: Juju Event
        """
        csr_secret = self.model.get_secret(label=self._get_csr_secret_label())
        csr_secret_content = csr_secret.get_content()
        if csr_secret_content["csr"].strip() != event.certificate_signing_request:
            logger.info("New certificate CSR doesn't match with the one stored.")
            return
        certificate_secret_content = {
            "certificate": event.certificate,
            "ca-certificate": event.ca,
            "chain": json.dumps(event.chain),
            "csr": event.certificate_signing_request,
        }
        if self._certificate_is_stored:
            certificate_secret = self.model.get_secret(label=self._get_certificate_secret_label())
            certificate_secret.set_content(content=certificate_secret_content)
        else:
            self.unit.add_secret(
                content=certificate_secret_content,
                label=self._get_certificate_secret_label(),
            )
        logger.info(f"New certificate is stored: {event.certificate}")
        self.unit.status = ActiveStatus("Certificate is available")

    def _on_certificates_relation_joined(self, event: EventBase) -> None:
        """Validates config and requests a new certificate.

        Args:
            event: Juju event.
        """
        if not self._csr_is_stored:
            self._generate_csr(common_name=self._get_unit_common_name())
        if not self._certificate_is_stored:
            self._request_certificate()
            self.unit.status = ActiveStatus("Certificate request is sent")

    def _get_unit_common_name(self) -> str:
        """Returns common name for the unit.

        If `common_name` config option is set, it will be used as a common name.
        Otherwise, the common name will be generated based on the application name and unit number.
        """
        config_common_name = self.model.config.get("common_name")
        if config_common_name:
            return config_common_name
        return f"{self.app.name}-{self._get_unit_number()}.{self.model.name}"

    def _revoke_existing_certificates(self) -> None:
        if not self._csr_is_stored:
            return
        secret = self.model.get_secret(label=self._get_csr_secret_label())
        secret_content = secret.get_content()
        self.certificates.request_certificate_revocation(
            certificate_signing_request=secret_content["csr"].encode()
        )

    def _request_certificate(self) -> None:
        """Requests X.509 certificate.

        Retrieves private key and password from Juju secret, generates a certificate
        signing request (CSR) and inserts it into the `certificates` relation unit relation data.
        """
        if not self._csr_is_stored:
            raise RuntimeError("CSR is not stored")
        csr_secret = self.model.get_secret(label=self._get_csr_secret_label())
        csr_secret_content = csr_secret.get_content()
        self.certificates.request_certificate_creation(
            certificate_signing_request=csr_secret_content["csr"].encode()
        )

    def _generate_csr(self, common_name: str) -> None:
        """Generates CSR based on private key and stores it in Juju secret."""
        if not self._private_key_is_stored:
            raise RuntimeError("Private key not stored.")
        private_key_secret = self.model.get_secret(label=self._get_private_key_secret_label())
        private_key_secret_content = private_key_secret.get_content()
        csr = generate_csr(
            private_key=private_key_secret_content["private-key"].encode(),
            private_key_password=private_key_secret_content["private-key-password"].encode(),
            subject=common_name,
        )
        csr_secret_content = {"csr": csr.decode()}
        self.unit.add_secret(content=csr_secret_content, label=self._get_csr_secret_label())

    @property
    def _private_key_is_stored(self) -> bool:
        """Returns whether private key is stored.

        Returns:
            bool: Whether private key is stored.
        """
        return self._secret_exists(label=self._get_private_key_secret_label())

    @property
    def _csr_is_stored(self) -> bool:
        """Returns whether private key is stored.

        Returns:
            bool: Whether private key is stored.
        """
        return self._secret_exists(label=self._get_csr_secret_label())

    @property
    def _certificate_is_stored(self) -> bool:
        """Returns whether certificate is available in Juju secret.

        Returns:
            bool: Whether certificate is stored
        """
        return self._secret_exists(label=self._get_certificate_secret_label())

    def _secret_exists(self, label: str) -> bool:
        """Returns whether a given secret exists.

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
        if self._certificate_is_stored:
            secret = self.model.get_secret(label=self._get_certificate_secret_label())
            content = secret.get_content()
            event.set_results(
                {
                    "certificate": content["certificate"],
                    "ca-certificate": content["ca-certificate"],
                    "chain": json.loads(content["chain"]),
                    "csr": content["csr"],
                }
            )
        else:
            event.fail("Certificate not available")

    def _get_unit_number(self) -> str:
        return self.unit.name.split("/")[1]

    def _get_private_key_secret_label(self) -> str:
        return f"private-key-{self._get_unit_number()}"

    def _get_csr_secret_label(self) -> str:
        return f"csr-{self._get_unit_number()}"

    def _get_certificate_secret_label(self) -> str:
        return f"certificate-{self._get_unit_number()}"


def generate_password() -> str:
    """Generates a random string containing 64 bytes.

    Returns:
        str: Password
    """
    return secrets.token_hex(64)


if __name__ == "__main__":
    main(TLSRequirerOperatorCharm)
