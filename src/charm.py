#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm that requests X.509 certificates using the tls-certificates interface."""

import logging
import secrets
import string
from typing import Optional

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from ops.charm import ActionEvent, CharmBase, EventBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, SecretNotFoundError, WaitingStatus

logger = logging.getLogger(__name__)


PRIVATE_KEY_SECRET_LABEL = "private-key"
CSR_SECRET_LABEL = "csr"
CERTIFICATE_SECRET_LABEL = "certificate"


class TLSRequirerOperatorCharm(CharmBase):
    """TLS Requirer Operator Charm."""

    def __init__(self, *args):
        """Handles events for certificate management."""
        super().__init__(*args)
        self.certificates = TLSCertificatesRequiresV2(self, "certificates")
        self.framework.observe(self.on.config_changed, self._request_certificate_hook)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(
            self.on.certificates_relation_joined, self._request_certificate_hook
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )

    @property
    def _config_subject(self) -> Optional[str]:
        """Returns the user provided common name.

        Returns:
            str: Common name
        """
        return self.model.config.get("subject", None)

    @property
    def _certificates_relation_created(self) -> bool:
        return self._relation_created("certificates")

    def _relation_created(self, relation_name: str) -> bool:
        """Returns whether given relation was created.

        Args:
            relation_name (str): Relation name

        Returns:
            bool: True/False
        """
        try:
            if self.model.get_relation(relation_name):
                return True
            return False
        except KeyError:
            return False

    def _on_install(self, event: InstallEvent) -> None:
        """Generates password and private key and stores them in a Juju secret.

        Args:
            event: Juju event.
        """
        if not self.unit.is_leader():
            return
        private_key_password = generate_password()
        private_key = generate_private_key(password=private_key_password.encode())
        self.app.add_secret(
            content={
                "private-key-password": private_key_password,
                "private-key": private_key.decode(),
            },
            label=PRIVATE_KEY_SECRET_LABEL,
        )
        logger.info("Private key generated")

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Stores the certificate in a Juju secret.

        Args:
            event: Juju Event
        """
        if not self.unit.is_leader():
            return
        self.app.add_secret(
            content={
                "certificate": event.certificate,
                "ca-certificate": event.ca,
                "chain": event.chain,
                "csr": event.certificate_signing_request,
            },
            label=CERTIFICATE_SECRET_LABEL,
        )
        logger.info(f"New certificate is stored: {event.certificate}")
        self.unit.status = ActiveStatus()

    def _request_certificate_hook(self, event: EventBase) -> None:
        """Validates config and requests a new certificate.

        Args:
            event: Juju event.
        """
        if not self.unit.is_leader():
            return
        if not self._config_subject:
            self.unit.status = BlockedStatus("Config `subject` must be set.")
            return
        if not self._private_key_is_stored:
            self.unit.status = WaitingStatus(
                "Waiting for private key and password to be generated."
            )
            event.defer()
            return
        if self._certificates_relation_created:
            self._request_certificate()

    def _request_certificate(self) -> None:
        """Requests X.509 certificate.

        Retrieves private key and password from Juju secret, generates a certificate
        signing request (CSR) and inserts it into the `certificates` relation unit relation data.
        """
        if not self._private_key_is_stored:
            raise RuntimeError("Private key not stored.")
        private_key_secret = self.model.get_secret(label=PRIVATE_KEY_SECRET_LABEL)
        private_key_secret_content = private_key_secret.get_content()
        csr = generate_csr(
            private_key=private_key_secret_content["private-key"].encode(),
            private_key_password=private_key_secret_content["private-key-password"].encode(),
            subject=self._config_subject,
        )
        self.certificates.request_certificate_creation(certificate_signing_request=csr)
        self.app.add_secret(content={"csr": csr.decode()}, label=CSR_SECRET_LABEL)
        self.unit.status = WaitingStatus("Waiting for certificate to be available")

    @property
    def _private_key_is_stored(self) -> bool:
        """Returns whether private key is stored.

        Returns:
            bool: Whether private key is stored.
        """
        try:
            self.model.get_secret(label=PRIVATE_KEY_SECRET_LABEL)
            return True
        except SecretNotFoundError:
            return False

    @property
    def _certificate_is_available(self) -> bool:
        """Returns whether certificate is available in Juju secret.

        Returns:
            bool: Whether certificate is stored
        """
        try:
            secret = self.model.get_secret(label=CERTIFICATE_SECRET_LABEL)
            content = secret.get_content()
            if content.get("certificate", None):
                return True
            else:
                return False
        except SecretNotFoundError:
            return False

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `get-certificate` Juju action.

        Args:
            event: Juju event
        """
        if not self.unit.is_leader():
            return
        if self._certificate_is_available:
            secret = self.model.get_secret(label=CERTIFICATE_SECRET_LABEL)
            content = secret.get_content()
            event.set_results(
                {
                    "certificate": content["certificate"],
                    "ca-certificate": content["ca-certificate"],
                    "chain": content["chain"],
                }
            )
        else:
            event.fail("Certificate not available")


def generate_password() -> str:
    """Generates a random 12 character password.

    Returns:
        str: Password
    """
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(12))


if __name__ == "__main__":
    main(TLSRequirerOperatorCharm)
