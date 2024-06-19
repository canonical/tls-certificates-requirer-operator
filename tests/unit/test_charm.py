# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import datetime
import unittest
from unittest.mock import Mock, patch

import pytest
from charm import TLSRequirerCharm
from ops import testing
from ops.model import ActiveStatus, SecretNotFoundError
from tls import generate_csr, generate_private_key

from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    PrivateKey,
    ProviderCertificate,
)

PRIVATE_KEY_PASSWORD = "whatever password"
COMMON_NAME = "banana.com"
ORGANIZATION_NAME = "Canonical"
EMAIL_ADDRESS = "canonical@ubuntu.com"
COUNTRY_NAME = "CA"
STATE_OR_PROVINCE_NAME = "QC"
LOCALITY_NAME = "Montreal"
CA = "whatever ca"
CERTIFICATE = "whatever certificate"


class TestCharmUnitMode(unittest.TestCase):
    def setUp(self):
        self.private_key = generate_private_key(password=PRIVATE_KEY_PASSWORD.encode())
        self.csr = generate_csr(
            sans_dns=[COMMON_NAME],
            common_name=COMMON_NAME,
            organization_name=ORGANIZATION_NAME,
            email_address=EMAIL_ADDRESS,
            country_name=COUNTRY_NAME,
            state_or_province_name=STATE_OR_PROVINCE_NAME,
            locality_name=LOCALITY_NAME,
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
        )
        self.model_name = "whatever"
        self.harness = testing.Harness(TLSRequirerCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_model_name(self.model_name)
        self.harness.update_config({"mode": "unit"})
        self.harness.begin()

    def _add_model_secret(self, owner: str, content: dict, label: str) -> None:
        """Add a secret to the model.

        Args:
            owner: Secret owner.
            content: Secret content.
            label: Secret label.
        """
        secret_id = self.harness.add_model_secret(
            owner=owner,
            content=content,
        )
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label=label)

    def _store_unit_private_key(self):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "private-key": self.private_key.decode(),
                "private-key-password": PRIVATE_KEY_PASSWORD,
            },
            label="private-key-0",
        )

    def test_given_certificate_request_is_made_when_evaluate_status_then_status_is_active(
        self,
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={"csr": self.csr.decode()},
            label="csr-0",
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        self.harness.update_config(
            {
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            }
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("Waiting for unit certificate"),
        )

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_csrs_match_when_on_certificate_available_then_certificate_is_stored(
        self,
        patch_get_assigned_certificate,
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={"csr": self.csr.decode()},
            label="csr-0",
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            ),
            PrivateKey(
                private_key=self.private_key.decode(),
                password=PRIVATE_KEY_PASSWORD,
            ),
        )

        self.harness.update_config(
            {
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            }
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        secret = self.harness.model.get_secret(label="certificate-0")
        secret_content = secret.get_content(refresh=True)
        self.assertEqual(secret_content["certificate"], CERTIFICATE)
        self.assertEqual(secret_content["ca-certificate"], CA)
        self.assertEqual(
            secret_content["csr"],
            self.csr.decode(),
        )

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_stored_when_on_evaluate_status_then_status_is_active(
        self,
        patch_get_assigned_certificate,
    ):
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            ),
            PrivateKey(
                private_key=self.private_key.decode(),
                password=PRIVATE_KEY_PASSWORD,
            ),
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={"csr": self.csr.decode()},
            label="csr-0",
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
            },
            label="certificate-0",
        )
        self.harness.update_config(
            {
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            }
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("Unit certificate is available"),
        )

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_already_stored_when_new_matching_certificate_available_then_certificate_is_overwritten(  # noqa: E501
        self, patch_get_assigned_certificate
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "csr": self.csr.decode(),
            },
            label="csr-0",
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
            },
            label="certificate-0",
        )
        self.harness.update_config(
            {
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            }
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate="New certificate content",
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            ),
            PrivateKey(
                private_key=self.private_key.decode(),
                password=PRIVATE_KEY_PASSWORD,
            ),
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        secret_content = self.harness.model.get_secret(label="certificate-0").get_content(
            refresh=True
        )
        self.assertEqual(secret_content["certificate"], "New certificate content")

    def test_given_certificate_is_not_stored_when_on_get_certificate_action_then_event_fails(self):
        event = Mock()
        self.harness.set_leader(is_leader=True)

        self.harness.charm._on_get_certificate_action(event=event)

        event.fail.assert_called()

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_is_stored_when_on_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        patch_get_assigned_certificate,
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
                "csr": self.csr.decode(),
            },
            label="certificate-0",
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "csr": self.csr.decode(),
            },
            label="csr-0",
        )

        self.harness.set_leader(is_leader=True)

        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=0,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            ),
            PrivateKey(
                private_key=self.private_key.decode(),
                password=PRIVATE_KEY_PASSWORD,
            ),
        )
        event = Mock()
        self.harness.charm._on_get_certificate_action(event=event)

        event.set_results.assert_called_with(
            {
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
                "csr": self.csr.decode(),
            }
        )

    def test_given_certificate_is_stored_when_on_certificates_relation_broken_then_certificate_secret_is_removed(  # noqa: E501
        self,
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "csr": self.csr.decode(),
            },
            label="csr-0",
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "certificate": "whatever",
                "ca-certificate": CA,
            },
            label="certificate-0",
        )

        self.harness.charm._on_certificates_relation_broken(event=Mock())

        with pytest.raises(SecretNotFoundError):
            self.harness.model.get_secret(label="certificate-0")


class TestCharmAppMode(unittest.TestCase):
    def setUp(self):
        self.private_key = generate_private_key(password=PRIVATE_KEY_PASSWORD.encode())
        self.csr = generate_csr(
            sans_dns=[COMMON_NAME],
            common_name=COMMON_NAME,
            organization_name=ORGANIZATION_NAME,
            email_address=EMAIL_ADDRESS,
            country_name=COUNTRY_NAME,
            state_or_province_name=STATE_OR_PROVINCE_NAME,
            locality_name=LOCALITY_NAME,
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
        )
        self.model_name = "whatever"
        self.harness = testing.Harness(TLSRequirerCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_model_name(self.model_name)
        self.harness.set_leader(is_leader=True)
        self.harness.update_config({"mode": "app"})
        self.harness.begin()

    def _add_model_secret(self, owner: str, content: dict, label: str) -> None:
        """Add a secret to the model.

        Args:
            owner: Secret owner.
            content: Secret content.
            label: Secret label.
        """
        secret_id = self.harness.add_model_secret(
            owner=owner,
            content=content,
        )
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label=label)

    def _store_app_private_key(self):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={
                "private-key": self.private_key.decode(),
                "private-key-password": PRIVATE_KEY_PASSWORD,
            },
            label="private-key",
        )

    def test_given_certificate_request_is_made_when_evaluate_status_then_status_is_active(
        self,
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr.decode()},
            label="csr",
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        self.harness.update_config(
            {
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            }
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("Waiting for app certificate"),
        )

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_csrs_match_when_on_certificate_available_then_certificate_is_stored(
        self,
        patch_get_assigned_certificate,
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr.decode()},
            label="csr",
        )

        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            ),
            PrivateKey(
                private_key=self.private_key.decode(),
                password=PRIVATE_KEY_PASSWORD,
            ),
        )

        self.harness.update_config(
            {
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            }
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        secret = self.harness.model.get_secret(label="certificate")
        secret_content = secret.get_content(refresh=True)
        self.assertEqual(secret_content["certificate"], CERTIFICATE)
        self.assertEqual(secret_content["ca-certificate"], CA)
        self.assertEqual(
            secret_content["csr"],
            self.csr.decode(),
        )

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_stored_when_on_evaluate_status_then_status_is_active(
        self,
        patch_get_assigned_certificate,
    ):
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            ),
            PrivateKey(
                private_key=self.private_key.decode(),
                password=PRIVATE_KEY_PASSWORD,
            ),
        )
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr.decode()},
            label="csr",
        )

        self.harness.update_config(
            {
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            }
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("App certificate is available"),
        )

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_already_stored_when_new_matching_certificate_available_then_certificate_is_overwritten(  # noqa: E501
        self, patch_get_assigned_certificate
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={
                "csr": self.csr.decode(),
            },
            label="csr",
        )
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={
                "certificate": "old certificate",
                "ca-certificate": "old ca certificate",
            },
            label="certificate",
        )
        self.harness.update_config(
            {
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            }
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        self.harness.set_leader(is_leader=True)

        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate="New certificate content",
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            ),
            PrivateKey(
                private_key=self.private_key.decode(),
                password=PRIVATE_KEY_PASSWORD,
            ),
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        secret_content = self.harness.model.get_secret(label="certificate").get_content(
            refresh=True
        )
        self.assertEqual(secret_content["certificate"], "New certificate content")

    def test_given_certificate_is_not_stored_when_on_get_certificate_action_then_event_fails(self):
        event = Mock()

        self.harness.charm._on_get_certificate_action(event=event)

        event.fail.assert_called()

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_is_stored_when_on_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        patch_get_assigned_certificate,
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
                "csr": self.csr.decode(),
            },
            label="certificate",
        )
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={
                "csr": self.csr.decode(),
            },
            label="csr",
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=0,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            ),
            PrivateKey(
                private_key=self.private_key.decode(),
                password=PRIVATE_KEY_PASSWORD,
            ),
        )
        event = Mock()

        self.harness.charm._on_get_certificate_action(event=event)

        event.set_results.assert_called_with(
            {
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
                "csr": self.csr.decode(),
            }
        )

    def test_given_certificate_is_stored_when_on_certificates_relation_broken_then_certificate_secret_is_removed(  # noqa: E501
        self,
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={
                "certificate": "whatever",
                "ca-certificate": CA,
            },
            label="certificate",
        )

        self.harness.charm._on_certificates_relation_broken(event=Mock())

        with pytest.raises(SecretNotFoundError):
            self.harness.model.get_secret(label="certificate")
