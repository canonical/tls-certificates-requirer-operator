# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import Mock, patch

import pytest
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, SecretNotFoundError, WaitingStatus

from charm import TLSRequirerOperatorCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(TLSRequirerOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("charm.generate_password")
    @patch("charm.generate_private_key")
    def test_given_unit_is_leader_when_on_install_then_private_key_is_generated(
        self,
        patch_generate_private_key,
        patch_generate_password,
    ):
        self.harness.set_leader(is_leader=True)
        private_key_password = "whatever password"
        private_key = "whatever private key"
        patch_generate_private_key.return_value = private_key.encode()
        patch_generate_password.return_value = private_key_password
        self.harness.charm.on.install.emit()

        secret = self.harness._backend.secret_get(label="private-key")

        self.assertEqual(secret["private-key"], private_key)
        self.assertEqual(secret["private-key-password"], private_key_password)

    def test_given_private_key_not_stored_when_on_config_changed_then_status_is_waiting(
        self,
    ):
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values={"subject": "banana.com"})

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for private key and password to be generated."),
        )

    def test_given_config_not_valid_when_on_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values={"subject": ""})

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Config `subject` must be set."),
        )

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation"  # noqa: E501, W505
    )
    @patch("charm.generate_csr")
    def test_given_private_key_is_stored_and_certificate_relation_is_created_when_on_config_changed_then_certificate_is_requested(  # noqa: E501
        self,
        patch_generate_csr,
        patch_request_certificate,
    ):
        private_key = "whatever private key"
        private_key_password = "whatever password"
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(
            label="private-key",
            content={
                "private-key": private_key,
                "private-key-password": private_key_password,
            },
        )
        patch_generate_csr.return_value = csr.encode()
        self.harness.add_relation(relation_name="certificates", remote_app="certificates-provider")

        self.harness.update_config(key_values={"subject": "banana.com"})

        patch_request_certificate.assert_called_with(certificate_signing_request=csr.encode())

    @patch("charm.generate_csr")
    def test_given_certificate_is_requested_when_on_config_changed_then_status_is_waiting(
        self,
        patch_generate_csr,
    ):
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(
            label="private-key",
            content={
                "private-key": "whatever private key",
                "private-key-password": "whatever password",
            },
        )
        patch_generate_csr.return_value = csr.encode()
        self.harness.add_relation(relation_name="certificates", remote_app="certificates-provider")

        self.harness.update_config(key_values={"subject": "banana.com"})

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for certificate to be available"),
        )

    @patch("charm.generate_csr")
    def test_given_certificate_relation_is_not_created_when_on_config_changed_then_csr_is_generated(  # noqa: E501
        self,
        patch_generate_csr,
    ):
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(
            label="private-key",
            content={
                "private-key": "whatever private key",
                "private-key-password": "whatever password",
            },
        )
        patch_generate_csr.return_value = csr.encode()

        self.harness.update_config(key_values={"subject": "banana.com"})

        secret = self.harness._backend.secret_get(label="csr")
        assert secret["csr"] == csr

    @patch("charm.generate_csr")
    def test_given_certificate_relation_is_not_created_when_on_config_changed_then_status_is_active(  # noqa: E501
        self,
        patch_generate_csr,
    ):
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(
            label="private-key",
            content={
                "private-key": "whatever private key",
                "private-key-password": "whatever password",
            },
        )
        patch_generate_csr.return_value = csr.encode()

        self.harness.update_config(key_values={"subject": "banana.com"})

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus(),
        )

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_csr_is_stored_when_certificates_relation_joined_then_certificate_is_requested(
        self,
        patch_request_certificate_creation,
    ):
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(label="csr", content={"csr": csr})
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=csr.encode()
        )

    def test_given_csr_is_stored_when_certificates_relation_joined_then_status_is_waiting(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(label="csr", content={"csr": "whatever csr"})
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for certificate to be available"),
        )

    def test_given_csr_not_stored_when_certificates_relation_joined_then_status_is_waiting(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for CSR to be generated."),
        )

    def test_given_csrs_match_when_on_certificate_available_then_certificate_is_stored(self):
        certificate = "whatever certificate"
        ca = "whatever ca"
        chain = ["whatever cert 1", "whatever cert 2"]
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(label="csr", content={"csr": csr})

        self.harness.charm._on_certificate_available(
            event=Mock(
                certificate=certificate,
                ca=ca,
                chain=chain,
                certificate_signing_request=csr,
            )
        )

        secret = self.harness._backend.secret_get(label="certificate")
        self.assertEqual(secret["certificate"], certificate)
        self.assertEqual(secret["ca-certificate"], ca)
        self.assertEqual(
            secret["chain"],
            json.dumps(chain),
        )
        self.assertEqual(
            secret["csr"],
            csr,
        )

    def test_given_certificate_already_stored_when_on_certificate_available_then_certificate_is_overwritten(  # noqa: E501
        self,
    ):
        certificate = "whatever certificate"
        ca = "whatever ca"
        chain = ["whatever cert 1", "whatever cert 2"]
        csr = "whatever csr"
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(label="csr", content={"csr": csr})
        self.harness._backend.secret_add(
            label="certificate",
            content={
                "certificate": "old certificate",
                "ca-certificate": "old ca certificate",
                "chain": "old chain",
            },
        )

        self.harness.charm._on_certificate_available(
            event=Mock(
                certificate=certificate,
                ca=ca,
                chain=chain,
                certificate_signing_request=csr,
            )
        )

        secret = self.harness._backend.secret_get(label="certificate")
        self.assertEqual(secret["certificate"], certificate)
        self.assertEqual(secret["ca-certificate"], ca)
        self.assertEqual(
            secret["chain"],
            json.dumps(chain),
        )
        self.assertEqual(
            secret["csr"],
            csr,
        )

    def test_given_certificate_is_not_stored_when_on_get_certificate_action_then_event_fails(self):
        event = Mock()
        self.harness.set_leader(is_leader=True)

        self.harness.charm._on_get_certificate_action(event=event)

        event.fail.assert_called()

    def test_given_certificate_is_stored_when_on_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=True)
        certificate = "whatever certificate"
        ca = "whatever ca"
        chain = "whatever chain"
        csr = "whatever csr"
        event = Mock()
        self.harness._backend.secret_add(
            label="certificate",
            content={
                "certificate": certificate,
                "ca-certificate": ca,
                "chain": chain,
                "csr": csr,
            },
        )

        self.harness.charm._on_get_certificate_action(event=event)

        event.set_results.assert_called_with(
            {
                "certificate": certificate,
                "ca-certificate": ca,
                "chain": chain,
                "csr": "whatever csr",
            }
        )

    def test_given_certificate_is_stored_when_on_certificates_relation_broken_then_certificate_secret_is_removed(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(
            label="certificate",
            content={
                "certificate": "whatever",
                "ca-certificate": "whatever ca",
                "chain": "whatever chain",
            },
        )

        self.harness.charm._on_certificates_relation_broken(event=Mock())

        with pytest.raises(SecretNotFoundError):
            self.harness._backend.secret_get(label="certificate")
