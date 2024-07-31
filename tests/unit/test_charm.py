# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, patch

import pytest
from charm import TLSRequirerCharm
from ops import testing
from ops.model import ActiveStatus, SecretNotFoundError
from tls import generate_ca, generate_certificate, generate_csr, generate_private_key

from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    PrivateKey,
    ProviderCertificate,
)

COMMON_NAME = "banana.com"
ORGANIZATION_NAME = "Canonical"
EMAIL_ADDRESS = "canonical@ubuntu.com"
COUNTRY_NAME = "CA"
STATE_OR_PROVINCE_NAME = "QC"
LOCALITY_NAME = "Montreal"

requirer_private_key = generate_private_key()
provider_private_key = generate_private_key()

CA = generate_ca(
    private_key=provider_private_key,
    common_name=COMMON_NAME,
)
CSR = generate_csr(
    private_key=requirer_private_key,
    common_name=COMMON_NAME,
    organization_name=ORGANIZATION_NAME,
    email_address=EMAIL_ADDRESS,
    country_name=COUNTRY_NAME,
    state_or_province_name=STATE_OR_PROVINCE_NAME,
    locality_name=LOCALITY_NAME,
    sans_dns=[COMMON_NAME],
)
CERTIFICATE = generate_certificate(
    csr=CSR,
    ca=CA,
    ca_key=provider_private_key,
)


class TestCharmUnitMode(unittest.TestCase):
    def setUp(self):
        self.private_key = generate_private_key()
        self.csr = generate_csr(
            sans_dns=[COMMON_NAME],
            common_name=COMMON_NAME,
            organization_name=ORGANIZATION_NAME,
            email_address=EMAIL_ADDRESS,
            country_name=COUNTRY_NAME,
            state_or_province_name=STATE_OR_PROVINCE_NAME,
            locality_name=LOCALITY_NAME,
            private_key=self.private_key,
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

    def test_given_certificate_request_is_made_when_evaluate_status_then_status_is_active(
        self,
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={"csr": self.csr},
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
            content={"csr": self.csr},
            label="csr-0",
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
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
        self.assertEqual(secret_content["csr"], self.csr)

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
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
                revoked=False,
            ),
            PrivateKey.from_string(self.private_key),
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={"csr": self.csr},
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
                "csr": self.csr,
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
        new_common_name = "pizza.com"
        new_csr = generate_csr(
            sans_dns=[new_common_name],
            common_name=new_common_name,
            organization_name=ORGANIZATION_NAME,
            email_address=EMAIL_ADDRESS,
            country_name=COUNTRY_NAME,
            state_or_province_name=STATE_OR_PROVINCE_NAME,
            locality_name=LOCALITY_NAME,
            private_key=self.private_key,
        )
        new_certificate = generate_certificate(
            csr=new_csr,
            ca=CA,
            ca_key=provider_private_key,
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                certificate=Certificate.from_string(new_certificate),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        secret_content = self.harness.model.get_secret(label="certificate-0").get_content(
            refresh=True
        )
        self.assertEqual(secret_content["certificate"], new_certificate)

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
                "csr": self.csr,
            },
            label="certificate-0",
        )
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "csr": self.csr,
            },
            label="csr-0",
        )

        self.harness.set_leader(is_leader=True)

        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )
        event = Mock()
        self.harness.charm._on_get_certificate_action(event=event)

        event.set_results.assert_called_with(
            {
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
                "csr": self.csr,
            }
        )

    def test_given_certificate_is_stored_when_on_certificates_relation_broken_then_certificate_secret_is_removed(  # noqa: E501
        self,
    ):
        self._add_model_secret(
            owner=self.harness.model.unit.name,
            content={
                "csr": self.csr,
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
        self.private_key = generate_private_key()
        self.csr = generate_csr(
            sans_dns=[COMMON_NAME],
            common_name=COMMON_NAME,
            organization_name=ORGANIZATION_NAME,
            email_address=EMAIL_ADDRESS,
            country_name=COUNTRY_NAME,
            state_or_province_name=STATE_OR_PROVINCE_NAME,
            locality_name=LOCALITY_NAME,
            private_key=self.private_key,
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

    def test_given_certificate_request_is_made_when_evaluate_status_then_status_is_active(
        self,
    ):
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr},
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
            content={"csr": self.csr},
            label="csr",
        )

        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
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
            self.csr,
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
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={"csr": self.csr},
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
                "csr": self.csr,
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

        new_common_name = "blou.ca"
        new_csr = generate_csr(
            sans_dns=[new_common_name],
            common_name=new_common_name,
            organization_name=ORGANIZATION_NAME,
            email_address=EMAIL_ADDRESS,
            country_name=COUNTRY_NAME,
            state_or_province_name=STATE_OR_PROVINCE_NAME,
            locality_name=LOCALITY_NAME,
            private_key=self.private_key,
        )
        new_certificate = generate_certificate(
            csr=new_csr,
            ca=CA,
            ca_key=provider_private_key,
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                certificate=Certificate.from_string(new_certificate),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        secret_content = self.harness.model.get_secret(label="certificate").get_content(
            refresh=True
        )
        self.assertEqual(secret_content["certificate"], new_certificate)

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
                "csr": self.csr,
            },
            label="certificate",
        )
        self._add_model_secret(
            owner=self.harness.model.app.name,
            content={
                "csr": self.csr,
            },
            label="csr",
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )
        event = Mock()

        self.harness.charm._on_get_certificate_action(event=event)

        event.set_results.assert_called_with(
            {
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
                "csr": self.csr,
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
