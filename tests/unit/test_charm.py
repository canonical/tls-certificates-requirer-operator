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

from lib.charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
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
        self.private_key = generate_private_key(
            password=PRIVATE_KEY_PASSWORD.encode()
        )
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

    @patch("charm.generate_csr")
    @patch("charm.generate_password")
    @patch("charm.generate_private_key")
    def test_given_when_on_install_then_private_key_is_generated(
        self,
        patch_generate_private_key,
        patch_generate_password,
        patch_generate_csr,
    ):
        patch_generate_private_key.return_value = self.private_key
        patch_generate_password.return_value = PRIVATE_KEY_PASSWORD
        patch_generate_csr.return_value = self.csr

        self.harness.charm.on.install.emit()

        secret = self.harness.model.get_secret(label="private-key-0")
        secret_content = secret.get_content(refresh=True)

        self.assertEqual(secret_content["private-key"], self.private_key.decode())
        self.assertEqual(secret_content["private-key-password"], PRIVATE_KEY_PASSWORD)

    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_private_key_is_stored_when_certificates_relation_joined_then_certificate_is_requested(  # noqa: E501
        self,
        patch_request_certificate_creation,
        patch_generate_csr,
    ):
        patch_generate_csr.return_value = self.csr
        self._store_unit_private_key()
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )
        unit_number = self.harness.model.unit.name.split("/")[1]
        patch_generate_csr.assert_called_with(
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
            subject=f"{self.harness.charm.app.name}-{unit_number}.{self.harness.model.name}",
            sans_dns=[f"{self.harness.charm.app.name}-{unit_number}.{self.harness.model.name}"],
            organization=None,
            email_address=None,
            country_name=None,
            state_or_province_name=None,
            locality_name=None,
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=self.csr
        )

    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_common_name_config_is_set_when_certificates_relation_joined_then_certificate_is_requested_with_common_name(  # noqa: E501
        self,
        patch_request_certificate_creation,
        patch_generate_csr,
    ):
        patch_generate_csr.return_value = self.csr
        self._store_unit_private_key()
        self.harness.update_config({"common_name": COMMON_NAME})
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        unit_number = self.harness.model.unit.name.split("/")[1]
        patch_generate_csr.assert_called_with(
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
            subject=COMMON_NAME,
            sans_dns=[f"{self.harness.charm.app.name}-{unit_number}.{self.harness.model.name}"],
            organization=None,
            email_address=None,
            country_name=None,
            state_or_province_name=None,
            locality_name=None,
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=self.csr
        )

    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_sans_dns_config_is_set_when_certificates_relation_joined_then_certificate_is_requested_with_sans_dns(  # noqa: E501
        self,
        patch_request_certificate_creation,
        patch_generate_csr,
    ):
        patch_generate_csr.return_value = self.csr
        self._store_unit_private_key()
        self.harness.update_config({"sans_dns": "banana.com,apple.com"})
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        unit_number = self.harness.model.unit.name.split("/")[1]
        patch_generate_csr.assert_called_with(
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
            subject=f"{self.harness.charm.app.name}-{unit_number}.{self.harness.model.name}",
            sans_dns=["banana.com", "apple.com"],
            organization=None,
            email_address=None,
            country_name=None,
            state_or_province_name=None,
            locality_name=None,
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=self.csr
        )

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_certificate_signing_requests"  # noqa: E501, W505
    )
    def test_given_certificate_request_is_made_when_evaluate_status_then_status_is_active(
        self,
        patch_get_certificate_signing_requests,
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

        patch_get_certificate_signing_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                unit_name=self.harness.model.unit.name,
                csr=self.csr.decode(),
                is_ca=False,
            )
        ]

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("Unit certificate request is sent"),
        )

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"  # noqa: E501, W505
    )
    def test_given_csrs_match_when_on_certificate_available_then_certificate_is_stored(
        self,
        patch_get_assigned_certificates,
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={"csr": self.csr.decode()},
            label="csr-0",
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            )
        ]

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

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"  # noqa: E501, W505
    )
    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_certificate_signing_requests"  # noqa: E501, W505
    )
    def test_given_certificate_stored_when_on_evaluate_status_then_status_is_active(
        self,
        patch_get_certificate_signing_requests,
        patch_get_assigned_certificates,
    ):
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_certificate_signing_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                unit_name=self.harness.model.unit.name,
                csr=self.csr.decode(),
                is_ca=False,
            )
        ]
        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            )
        ]
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

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"  # noqa: E501, W505
    )
    def test_given_certificate_already_stored_when_different_certificate_available_then_certificate_is_overwritten(  # noqa: E501
        self,
        patch_get_assigned_certificates
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

        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate="New certificate content",
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            )
        ]
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

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"  # noqa: E501, W505
    )
    def test_given_certificate_is_stored_when_on_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        patch_get_assigned_certificates,
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

        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=0,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            )
        ]
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
        self.harness.set_leader(is_leader=True)
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

    @patch("charm.generate_csr")
    def test_given_csr_stored_when_relation_joined_then_csr_not_generated_again(
        self, patch_generate_csr
    ):
        self.harness.set_leader(is_leader=True)
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={"csr": self.csr.decode()},
            label="csr-0",
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "private-key": self.private_key.decode(),
                "private-key-password": PRIVATE_KEY_PASSWORD,
            },
            label="private-key-0",
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

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        secret = self.harness.model.get_secret(label="csr-0")
        secret_content = secret.get_content(refresh=True)
        self.assertEqual(secret_content["csr"], self.csr.decode())
        patch_generate_csr.assert_not_called()

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_certificate_signing_requests"  # noqa: E501, W505)
    )
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_certificate_requested_when_configure_then_certificate_not_requested_again(
        self,
        patch_request_certificate_creation,
        patch_get_certificate_signing_requests,
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={"csr": self.csr.decode()},
            label="csr-0",
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
        patch_get_certificate_signing_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                unit_name=self.harness.model.unit.name,
                csr=self.csr.decode(),
                is_ca=False,
            )
        ]
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        patch_request_certificate_creation.assert_not_called()


class TestCharmAppMode(unittest.TestCase):
    def setUp(self):
        self.private_key = generate_private_key(
            password=PRIVATE_KEY_PASSWORD.encode()
        )
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

    @patch("charm.generate_csr")
    @patch("charm.generate_password")
    @patch("charm.generate_private_key")
    def test_given_when_on_install_then_private_key_is_generated(
        self,
        patch_generate_private_key,
        patch_generate_password,
        patch_generate_csr,
    ):
        patch_generate_private_key.return_value = self.private_key
        patch_generate_password.return_value = PRIVATE_KEY_PASSWORD
        patch_generate_csr.return_value = self.csr

        self.harness.charm.on.install.emit()

        secret = self.harness.model.get_secret(label="private-key")
        secret_content = secret.get_content(refresh=True)

        self.assertEqual(secret_content["private-key"], self.private_key.decode())
        self.assertEqual(secret_content["private-key-password"], PRIVATE_KEY_PASSWORD)


    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_private_key_is_stored_when_certificates_relation_joined_then_certificate_is_requested(  # noqa: E501
        self,
        patch_request_certificate_creation,
        patch_generate_csr,
    ):
        patch_generate_csr.return_value = self.csr
        self._store_app_private_key()
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )
        patch_generate_csr.assert_called_with(
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
            subject=f"{self.harness.charm.app.name}.{self.harness.model.name}",
            sans_dns=[f"{self.harness.charm.app.name}.{self.harness.model.name}"],
            organization=None,
            email_address=None,
            country_name=None,
            state_or_province_name=None,
            locality_name=None,
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=self.csr
        )


    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_common_name_config_is_set_when_certificates_relation_joined_then_certificate_is_requested_with_common_name(  # noqa: E501
        self,
        patch_request_certificate_creation,
        patch_generate_csr,
    ):
        patch_generate_csr.return_value = self.csr
        self._store_app_private_key()
        self.harness.update_config({"common_name": COMMON_NAME})
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        patch_generate_csr.assert_called_with(
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
            subject=COMMON_NAME,
            sans_dns=[f"{self.harness.charm.app.name}.{self.harness.model.name}"],
            organization=None,
            email_address=None,
            country_name=None,
            state_or_province_name=None,
            locality_name=None,
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=self.csr
        )

    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_sans_dns_config_is_set_when_certificates_relation_joined_then_certificate_is_requested_with_sans_dns(  # noqa: E501
        self,
        patch_request_certificate_creation,
        patch_generate_csr,
    ):
        patch_generate_csr.return_value = self.csr
        self._store_app_private_key()
        self.harness.update_config({"sans_dns": "banana.com,apple.com"})
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        patch_generate_csr.assert_called_with(
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
            subject=f"{self.harness.charm.app.name}.{self.harness.model.name}",
            sans_dns=["banana.com", "apple.com"],
            organization=None,
            email_address=None,
            country_name=None,
            state_or_province_name=None,
            locality_name=None,
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=self.csr
        )

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_certificate_signing_requests"  # noqa: E501, W505
    )
    def test_given_certificate_request_is_made_when_evaluate_status_then_status_is_active(
        self,
        patch_get_certificate_signing_requests,
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

        patch_get_certificate_signing_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                unit_name=self.harness.model.unit.name,
                csr=self.csr.decode(),
                is_ca=False,
            )
        ]

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("App certificate request is sent"),
        )

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"  # noqa: E501, W505
    )
    def test_given_csrs_match_when_on_certificate_available_then_certificate_is_stored(
        self,
        patch_get_assigned_certificates,
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr.decode()},
            label="csr",
        )

        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            )
        ]

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

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"  # noqa: E501, W505
    )
    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_certificate_signing_requests"  # noqa: E501, W505
    )
    def test_given_certificate_stored_when_on_evaluate_status_then_status_is_active(
        self,
        patch_get_certificate_signing_requests,
        patch_get_assigned_certificates,
    ):
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_certificate_signing_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                unit_name=self.harness.model.unit.name,
                csr=self.csr.decode(),
                is_ca=False,
            )
        ]
        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            )
        ]
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

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"  # noqa: E501, W505
    )
    def test_given_certificate_already_stored_when_different_certificate_available_then_certificate_is_overwritten(  # noqa: E501
        self,
        patch_get_assigned_certificates
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

        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                certificate="New certificate content",
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            )
        ]
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

    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"  # noqa: E501, W505
    )
    def test_given_certificate_is_stored_when_on_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        patch_get_assigned_certificates,
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
        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=0,
                application_name=self.harness.charm.app.name,
                certificate=CERTIFICATE,
                ca=CA,
                chain=[CA],
                revoked=False,
                expiry_time=datetime.datetime.now(),
                csr=self.csr.decode(),
            )
        ]
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

    @patch("charm.generate_csr")
    def test_given_csr_stored_when_relation_joined_then_csr_not_generated_again(
        self, patch_generate_csr
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr.decode()},
            label="csr",
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "private-key": self.private_key.decode(),
                "private-key-password": PRIVATE_KEY_PASSWORD,
            },
            label="private-key",
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

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        secret = self.harness.model.get_secret(label="csr")
        secret_content = secret.get_content(refresh=True)
        self.assertEqual(secret_content["csr"], self.csr.decode())
        patch_generate_csr.assert_not_called()

    @patch("charm.generate_csr")
    def test_given_csr_stored_when_config_changed_then_new_csr_is_stored(self, patch_generate_csr):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr.decode()},
            label="csr",
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "private-key": self.private_key.decode(),
                "private-key-password": PRIVATE_KEY_PASSWORD,
            },
            label="private-key",
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

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        new_common_name = "ubuntu.com"
        new_email_address = "new@ubuntu.com"
        new_organization_name = "Ubuntu"
        new_country_name = "US"
        new_state_or_province_name = "CA"
        new_locality_name = "SF"
        new_csr = generate_csr(
            sans_dns=[new_common_name],
            common_name=new_common_name,
            organization_name=new_organization_name,
            email_address=new_email_address,
            country_name=new_country_name,
            state_or_province_name=new_state_or_province_name,
            locality_name=new_locality_name,
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
        )
        patch_generate_csr.return_value = new_csr

        self.harness.update_config(
            {
                "common_name": new_common_name,
                "sans_dns": new_common_name,
                "organization_name": new_organization_name,
                "email_address": new_email_address,
                "country_name": new_country_name,
                "state_or_province_name": new_state_or_province_name,
                "locality_name": new_locality_name,
            }
        )
        patch_generate_csr.assert_called_with(
            private_key=self.private_key,
            private_key_password=PRIVATE_KEY_PASSWORD.encode(),
            subject=new_common_name,
            sans_dns=[new_common_name],
            organization=new_organization_name,
            email_address=new_email_address,
            country_name=new_country_name,
            state_or_province_name=new_state_or_province_name,
            locality_name=new_locality_name,
        )
        csr_secret = self.harness.model.get_secret(label="csr").get_content(refresh=True)
        self.assertEqual(csr_secret["csr"], new_csr.decode())


    @patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_certificate_signing_requests"  # noqa: E501, W505
    )
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_certificate_is_requested_when_configure_then_certificate_not_requested_again(
        self,
        patch_request_certificate_creation,
        patch_get_certificate_signing_requests,
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr.decode()},
            label="csr",
        )
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={
                "private-key": self.private_key.decode(),
                "private-key-password": PRIVATE_KEY_PASSWORD,
            },
            label="private-key",
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
        patch_get_certificate_signing_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                application_name=self.harness.charm.app.name,
                unit_name=self.harness.model.app.name,
                csr=self.csr.decode(),
                is_ca=False,
            )
        ]

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        patch_request_certificate_creation.assert_not_called()
