#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm that requests X.509 certificates using the tls-certificates interface."""

import json
import logging
import secrets
from typing import Optional

from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from ops.charm import (
    ActionEvent,
    CharmBase,
    ConfigChangedEvent,
    EventBase,
    InstallEvent,
    RelationBrokenEvent,
)
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
        self.framework.observe(self.on.config_changed, self._on_config_changed)
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
    def _config_subject(self) -> Optional[str]:
        """Returns the user provided common name.

        Returns:
            str: Common name
        """
        return self.model.config.get("subject", None)

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

    def _on_certificates_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Removes Certificate from juju secret.

        Args:
            event: Juju event.
        """
        if not self.unit.is_leader():
            return
        if self._certificate_is_stored:
            certificate_secret = self.model.get_secret(label=CERTIFICATE_SECRET_LABEL)
            certificate_secret.remove_all_revisions()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Stores the certificate in a Juju secret.

        Args:
            event: Juju Event
        """
        if not self.unit.is_leader():
            return
        csr_secret = self.model.get_secret(label=CSR_SECRET_LABEL)
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
            certificate_secret = self.model.get_secret(label=CERTIFICATE_SECRET_LABEL)
            certificate_secret.set_content(content=certificate_secret_content)
        else:
            self.app.add_secret(
                content=certificate_secret_content,
                label=CERTIFICATE_SECRET_LABEL,
            )
        logger.info(f"New certificate is stored: {event.certificate}")
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
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
        if not self._certificates_relation_created:
            self.unit.status = BlockedStatus("Waiting for certificates relation to be created.")
            event.defer()
            return

        self._revoke_existing_certificates()
        self._generate_csr()
        if not self._csr_is_stored:
            # This check is required because of a Juju bug: https://bugs.launchpad.net/juju/+bug/2034050  # noqa: E501, W505
            # If _request_certificate is called and stored CSR could not be found, RuntimeError happens.  # noqa: E501, W505
            self.unit.status = WaitingStatus("Waiting csr to be stored.")
            event.defer()
            return
        self._request_certificate()
        self.unit.status = WaitingStatus("Waiting for certificate to be available.")

    def _on_certificates_relation_joined(self, event: EventBase) -> None:
        """Validates config and requests a new certificate.

        Args:
            event: Juju event.
        """
        if not self.unit.is_leader():
            return
        if not self._csr_is_stored:
            self.unit.status = WaitingStatus("Waiting for CSR to be generated.")
            return
        self._request_certificate()
        self.unit.status = WaitingStatus("Waiting for certificate to be available")

    def _revoke_existing_certificates(self) -> None:
        if not self._csr_is_stored:
            return
        secret = self.model.get_secret(label=CSR_SECRET_LABEL)
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
        csr_secret = self.model.get_secret(label=CSR_SECRET_LABEL)
        csr_secret_content = csr_secret.get_content()
        self.certificates.request_certificate_creation(
            certificate_signing_request=csr_secret_content["csr"].encode()
        )

    def _generate_csr(self) -> None:
        """Generates CSR based on private key and stores it in Juju secret."""
        if not self._private_key_is_stored:
            raise RuntimeError("Private key not stored.")
        private_key_secret = self.model.get_secret(label=PRIVATE_KEY_SECRET_LABEL)
        private_key_secret_content = private_key_secret.get_content()
        csr = generate_csr(
            private_key=private_key_secret_content["private-key"].encode(),
            private_key_password=private_key_secret_content["private-key-password"].encode(),
            subject=self._config_subject,
        )
        csr_secret_content = {"csr": csr.decode()}
        if self._csr_is_stored:
            csr_secret = self.model.get_secret(label=CSR_SECRET_LABEL)
            csr_secret.set_content(content=csr_secret_content)
        else:
            self.app.add_secret(content=csr_secret_content, label=CSR_SECRET_LABEL)

    @property
    def _private_key_is_stored(self) -> bool:
        """Returns whether private key is stored.

        Returns:
            bool: Whether private key is stored.
        """
        return self._secret_exists(label=PRIVATE_KEY_SECRET_LABEL)

    @property
    def _csr_is_stored(self) -> bool:
        """Returns whether private key is stored.

        Returns:
            bool: Whether private key is stored.
        """
        return self._secret_exists(label=CSR_SECRET_LABEL)

    @property
    def _certificate_is_stored(self) -> bool:
        """Returns whether certificate is available in Juju secret.

        Returns:
            bool: Whether certificate is stored
        """
        return self._secret_exists(label=CERTIFICATE_SECRET_LABEL)

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
        if not self.unit.is_leader():
            return
        if self._certificate_is_stored:
            secret = self.model.get_secret(label=CERTIFICATE_SECRET_LABEL)
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


def generate_password() -> str:
    """Generates a random string containing 64 bytes.

    Returns:
        str: Password
    """
    return secrets.token_hex(64)


if __name__ == "__main__":
    main(TLSRequirerOperatorCharm)
