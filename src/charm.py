#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm that requests X.509 certificates using the tls-certificates interface."""

import json
import logging
from typing import Any, FrozenSet, List, Optional, Tuple

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    Mode,
    TLSCertificatesRequiresV4,
)
from ops.charm import ActionEvent, CharmBase, CollectStatusEvent, RelationBrokenEvent
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, ModelError, SecretNotFoundError, StatusBase

logger = logging.getLogger(__name__)


class TLSRequirerCharm(CharmBase):
    """TLS Requirer Charm."""

    def __init__(self, *args: Any):
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
        if self._get_config_common_name() and not self.unit.is_leader():
            logger.warning("Only leader unit will request a certificate with a custom common name")
            return
        if mode == Mode.APP and not self.unit.is_leader():
            logger.warning("Only leader unit will request a certificate in app mode")
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
        # Subscribe to TLS requires-side events once
        self.framework.observe(
            self.certificates.on.certificate_denied, self._on_certificate_denied
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
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
        is_valid, msg = self._config_is_valid()
        if not is_valid:
            event.add_status(BlockedStatus(f"Invalid configuration: {msg}"))
            return
        # If provider reported request errors for our CSRs, reflect them as BlockedStatus.
        denied_message = self._get_provider_denied_message_for_our_csrs()
        if denied_message:
            event.add_status(BlockedStatus(denied_message))
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
        return ActiveStatus(self._get_certificate_fulfillment_status())

    def _collect_status_app_mode(self) -> StatusBase:
        """Collect status for the app mode."""
        if not self.unit.is_leader():
            return BlockedStatus("This charm can't scale when deployed in app mode")
        if not self._certificates_relation_created:
            return ActiveStatus("Waiting for certificates relation")
        return ActiveStatus(self._get_certificate_fulfillment_status())

    def _configure(self, event: EventBase) -> None:
        """Manage certificate lifecycle."""
        is_valid, msg = self._config_is_valid()
        if not is_valid:
            logger.error("Invalid configuration: %s", msg)
            return
        mode = self._get_config_mode()
        assert mode
        if not self._certificates_relation_created:
            return
        if mode == Mode.APP and not self.unit.is_leader():
            return
        for certificate_request in self._get_certificate_requests():
            if not self._certificate_is_stored(certificate_request=certificate_request):
                self._store_certificate(mode=mode, certificate_request=certificate_request)

    def _on_certificates_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Remove Certificate from juju secret.

        Args:
            event: Juju event.
        """
        for certificate_request in self._get_certificate_requests():
            if self._certificate_secret_exists(certificate_request=certificate_request):
                try:
                    certificate_secret = self.model.get_secret(
                        label=self._get_certificate_secret_label(
                            certificate_request=certificate_request
                        )
                    )
                except (SecretNotFoundError, ModelError):
                    logger.warning(
                        "Unable to retrieve certificate secret: %s",
                        certificate_request.common_name,
                    )
                    return
                try:
                    certificate_secret.remove_all_revisions()
                except (SecretNotFoundError, ModelError):
                    logger.warning(
                        "Unable to remove certificate secret: %s",
                        certificate_request.common_name,
                    )
                    return

    def _get_certificate_fulfillment_status(self) -> str:
        """Return the status message reflecting how many certificate requests are still pending."""
        assigned_certs, _ = self.certificates.get_assigned_certificates()
        assigned_certificates_num = len(assigned_certs)
        certificate_requests_num = len(self._get_certificate_requests())
        return f"{assigned_certificates_num}/{certificate_requests_num} certificate requests are fulfilled"  # noqa: E501

    def _get_certificate_requests(self) -> List[CertificateRequestAttributes]:
        return [
            CertificateRequestAttributes(
                common_name=self._get_common_name(i),
                sans_dns=self._get_sans_dns(i),
                organization=self._get_config_organization_name(),
                email_address=self._get_config_email_address(),
                country_name=self._get_config_country_name(),
                state_or_province_name=self._get_config_state_or_province_name(),
                locality_name=self._get_config_locality_name(),
                is_ca=self._get_config_is_ca(),
            )
            for i in range(self._get_config_num_certificates())
        ]

    def _certificate_is_stored(self, certificate_request: CertificateRequestAttributes) -> bool:
        """Return whether certificate is available in Juju secret."""
        if not self._certificate_secret_exists(certificate_request=certificate_request):
            return False
        try:
            stored_certificate_secret = self.model.get_secret(
                label=self._get_certificate_secret_label(certificate_request=certificate_request)
            )
        except SecretNotFoundError:
            logger.warning("Unable to retrieve certificate secret")
            return False
        stored_certificate = stored_certificate_secret.get_content(refresh=True)["certificate"]
        assigned_certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=certificate_request
        )
        if not assigned_certificate:
            return False
        return str(assigned_certificate.certificate) == stored_certificate

    def _store_certificate(
        self, mode: Mode, certificate_request: CertificateRequestAttributes
    ) -> None:
        """Store the assigned certificate in a Juju secret."""
        assigned_certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=certificate_request
        )
        if not assigned_certificate:
            logger.info("No certificate is assigned")
            return
        certificate_secret_content = {
            "certificate": str(assigned_certificate.certificate),
            "ca-certificate": str(assigned_certificate.ca),
            "csr": str(assigned_certificate.certificate_signing_request),
        }
        try:
            certificate_secret = self.model.get_secret(
                label=self._get_certificate_secret_label(certificate_request=certificate_request)
            )
        except SecretNotFoundError:
            if mode == Mode.UNIT:
                self.unit.add_secret(
                    content=certificate_secret_content,
                    label=self._get_certificate_secret_label(
                        certificate_request=certificate_request
                    ),
                )
            elif mode == Mode.APP:
                self.app.add_secret(
                    content=certificate_secret_content,
                    label=self._get_certificate_secret_label(
                        certificate_request=certificate_request
                    ),
                )
            logger.info(
                "New certificate is stored: %s", assigned_certificate.certificate.common_name
            )
            return
        certificate_secret.set_content(content=certificate_secret_content)
        logger.info("Certificate is updated: %s", assigned_certificate.certificate.common_name)

    def _get_config_common_name(self) -> Optional[str]:
        """Return common name from the configuration."""
        return self._get_str_config("common_name")

    def _get_common_name(self, certificate_number: int) -> str:
        """Return common name.

        If `common_name` config option is set, it will be used as a common name.
        Otherwise, the common name will be generated based on the application name and unit number:
        - `unit`: `cert-<certificate number>.unit-<unit number>.<app name>.<model name>`
        - `app`: `cert-<certificate number>.<app name>.<model name>`
        """
        config_common_name = self._get_config_common_name()
        if config_common_name:
            return config_common_name
        mode = self._get_config_mode()
        if mode == Mode.UNIT:
            return f"cert-{certificate_number}.unit-{self._get_unit_number()}.{self.app.name}.{self.model.name}"  # noqa: E501
        elif mode == Mode.APP:
            return f"cert-{certificate_number}.{self.app.name}.{self.model.name}"
        raise ValueError("Invalid mode, only 'unit' and 'app' are allowed.")

    def _config_is_valid(self) -> Tuple[bool, str]:
        """Return whether the configuration is valid."""
        if self._get_config_num_certificates() > 1 and self._get_config_common_name():
            return False, "Common name can't be set when requesting multiple certificates"
        config_mode = self._get_config_mode()
        if config_mode not in [Mode.UNIT, Mode.APP]:
            return False, "Invalid mode configuration: only 'unit' and 'app' are allowed"
        return True, ""

    def _get_config_num_certificates(self) -> int:
        """Return the number of certificates to request."""
        num_certificates = self.model.config.get("num_certificates", 1)
        if not isinstance(num_certificates, int):
            return 1
        return num_certificates

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

    def _get_sans_dns(self, certificate_number: int) -> FrozenSet[str]:
        """Return DNS Subject Alternative Names.

        If `sans_dns` config option is set, it will be used as a list of DNS
        Subject Alternative Names. Otherwise, the list will contain a single
        DNS Subject Alternative Name based on the application name and unit number:
        - `unit`: `cert-<certificate number>.unit-<unit number>.<app name>.<model name>`
        - `app`: `cert-<certificate number>.<app name>.<model name>`
        """
        config_sans_dns = self.model.config.get("sans_dns", "")
        if config_sans_dns and isinstance(config_sans_dns, str):
            return frozenset(config_sans_dns.split(","))
        mode = self._get_config_mode()
        if mode == Mode.UNIT:
            return frozenset(
                [
                    f"cert-{certificate_number}.unit-{self._get_unit_number()}.{self.app.name}.{self.model.name}"
                ]
            )
        elif mode == Mode.APP:
            return frozenset([f"cert-{certificate_number}.{self.app.name}.{self.model.name}"])
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

    def _get_config_is_ca(self) -> bool:
        """Return whether the certificate is a CA."""
        is_ca = self.model.config.get("is_ca", False)
        if not isinstance(is_ca, bool):
            return False
        return is_ca

    def _get_str_config(self, key: str) -> Optional[str]:
        """Return value of specified string juju config."""
        value = self.model.config.get(key, None)
        if not value or not isinstance(value, str):
            return None
        return value

    def _certificate_secret_exists(
        self, certificate_request: CertificateRequestAttributes
    ) -> bool:
        return self._secret_exists(
            label=self._get_certificate_secret_label(certificate_request=certificate_request)
        )

    def _secret_exists(self, label: str) -> bool:
        """Return whether a given secret exists."""
        try:
            self.model.get_secret(label=label)
            return True
        except (SecretNotFoundError, KeyError):
            return False

    def _get_provider_denied_message_for_our_csrs(self) -> Optional[str]:
        """Return a BlockedStatus message if any of our CSRs were denied by the provider.

        Reads provider-side request_errors from the certificates relation app databag and
        matches them against our current CSR strings. Returns the first matching denial message,
        or None if no denial applies to our requests.
        """
        try:
            relation = self.model.get_relation("certificates")
        except KeyError:
            relation = None
        if not relation or not relation.app:
            return None
        try:
            raw = relation.data[relation.app].get("request_errors")
        except KeyError:
            raw = None
        if not raw:
            return None
        try:
            entries = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        our_csr_strings = {
            str(req.certificate_signing_request)
            for req in self.certificates.get_csrs_from_requirer_relation_data()
        }
        for entry in entries:
            try:
                if entry.get("csr") not in our_csr_strings:
                    continue
                error = entry.get("error", {}) or {}
                code = str(error.get("code", "")).upper()
                if code == "IP_NOT_ALLOWED":
                    return "CSR contains IP SANs not allowed by provider role"
                if code == "DOMAIN_NOT_ALLOWED":
                    return "Requested CN/SANs not allowed by provider role"
                if code == "WILDCARD_NOT_ALLOWED":
                    return "Wildcard DNS names are not allowed by provider role"
                provider_msg = error.get("message") or "unknown reason"
                return f"Certificate request denied: {provider_msg}"
            except Exception:
                # Ignore malformed entries; continue checking others
                continue
        return None

    def _on_certificate_denied(self, event: EventBase) -> None:
        """Set BlockedStatus with a clear message and warn-log when a CSR is denied."""
        relation_id = self._find_relation_id_for_csr(event.certificate_signing_request)
        cn = event.certificate_signing_request.common_name
        code_obj = getattr(event, "error", None)
        code_value = getattr(code_obj, "code", None)
        code_name = getattr(code_value, "name", str(code_value)) if code_value is not None else "UNKNOWN"
        if code_name == "IP_NOT_ALLOWED":
            message = "CSR contains IP SANs not allowed by provider role"
        elif code_name == "DOMAIN_NOT_ALLOWED":
            message = "Requested CN/SANs not allowed by provider role"
        elif code_name == "WILDCARD_NOT_ALLOWED":
            message = "Wildcard DNS names are not allowed by provider role"
        else:
            provider_msg = getattr(code_obj, "message", "unknown reason")
            message = f"Certificate request denied: {provider_msg}"
        # Idempotent: only update/log if changed
        current_status = self.unit.status
        if isinstance(current_status, BlockedStatus) and str(current_status) == message:
            return
        self.unit.status = BlockedStatus(message)
        logger.warning(
            "Relation %s: CSR CN %s denied with code %s: %s",
            relation_id if relation_id is not None else "unknown",
            cn,
            code_name,
            getattr(code_obj, "message", message),
        )

    def _on_certificate_available(self, event: EventBase) -> None:
        """Clear BlockedStatus when a certificate becomes available for our CSR."""
        relation_id = self._find_relation_id_for_csr(event.certificate_signing_request)
        if relation_id is None:
            return
        if isinstance(self.unit.status, BlockedStatus):
            new_status = ActiveStatus(self._get_certificate_fulfillment_status())
            if str(self.unit.status) != str(new_status):
                self.unit.status = new_status
                logger.info(
                    "Relation %s: CSR CN %s certificate available; clearing blocked status",
                    relation_id,
                    event.certificate_signing_request.common_name,
                )

    def _find_relation_id_for_csr(self, csr: Any) -> Optional[int]:
        """Return relation id for a CSR that matches one of our requests."""
        try:
            for req in self.certificates.get_csrs_from_requirer_relation_data():
                if str(req.certificate_signing_request) == str(csr):
                    return req.relation_id
        except Exception:
            return None
        return None

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `get-certificate` Juju action.

        Args:
            event: Juju event
        """
        is_valid, msg = self._config_is_valid()
        if not is_valid:
            event.fail(f"Invalid configuration: {msg}")
            return
        certificates = []
        for certificate_request in self._get_certificate_requests():
            if self._certificate_is_stored(certificate_request=certificate_request):
                secret = self.model.get_secret(
                    label=self._get_certificate_secret_label(
                        certificate_request=certificate_request
                    )
                )
                content = secret.get_content(refresh=True)
                certificates.append(
                    {
                        "certificate": content["certificate"],
                        "ca-certificate": content["ca-certificate"],
                        "csr": content["csr"],
                    }
                )
            else:
                event.fail(f"Certificate not available: {certificate_request.common_name}")
        event.set_results({"certificates": json.dumps(certificates)})

    def _get_unit_number(self) -> str:
        return self.unit.name.split("/")[1]

    def _get_certificate_secret_label(
        self, certificate_request: CertificateRequestAttributes
    ) -> str:
        return certificate_request.common_name


if __name__ == "__main__":
    main(TLSRequirerCharm)
