# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import Mock, patch

import pytest
from ops import testing
from ops.model import ActiveStatus, SecretNotFoundError

from charm import TLSRequirerOperatorCharm

PRIVATE_KEY = "whatever private key"
PRIVATE_KEY_PASSWORD = "whatever password"
CSR = "whatever csr"
SUBJECT = "banana.com"
CA = "whatever ca"
CERTIFICATE = "whatever certificate"


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(TLSRequirerOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def add_secret_for_private_key(self, private_key: str, private_key_password: str) -> None:
        self.harness._backend.secret_add(
            label="private-key-0",
            content={
                "private-key": private_key,
                "private-key-password": private_key_password,
            },
        )

    @patch("charm.generate_password")
    @patch("charm.generate_private_key")
    def test_given_unit_is_leader_when_on_install_then_private_key_is_generated(
        self,
        patch_generate_private_key,
        patch_generate_password,
    ):
        self.harness.set_leader(is_leader=True)
        patch_generate_private_key.return_value = PRIVATE_KEY.encode()
        patch_generate_password.return_value = PRIVATE_KEY_PASSWORD
        self.harness.charm.on.install.emit()

        secret = self.harness._backend.secret_get(label="private-key-0")

        self.assertEqual(secret["private-key"], PRIVATE_KEY)
        self.assertEqual(secret["private-key-password"], PRIVATE_KEY_PASSWORD)

    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_private_key_is_stored_when_certificates_relation_joined_then_certificate_is_requested(  # noqa: E501
        self,
        patch_request_certificate_creation,
        patch_generate_csr,
    ):
        patch_generate_csr.return_value = CSR.encode()
        self.harness.set_leader(is_leader=True)
        self.add_secret_for_private_key(
            private_key=PRIVATE_KEY, private_key_password=PRIVATE_KEY_PASSWORD
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=CSR.encode()
        )

    @patch("charm.generate_csr")
    def test_given_private_key_is_stored_when_certificates_relation_joined_then_status_is_waiting(
        self, patch_generate_csr
    ):
        patch_generate_csr.return_value = CSR.encode()
        self.harness.set_leader(is_leader=True)
        self.add_secret_for_private_key(
            private_key=PRIVATE_KEY, private_key_password=PRIVATE_KEY_PASSWORD
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("Certificate request is sent"),
        )

    def test_given_csrs_match_when_on_certificate_available_then_certificate_is_stored(self):
        chain = ["whatever cert 1", "whatever cert 2"]
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(label="csr-0", content={"csr": CSR})

        self.harness.charm._on_certificate_available(
            event=Mock(
                certificate=CERTIFICATE,
                ca=CA,
                chain=chain,
                certificate_signing_request=CSR,
            )
        )

        secret = self.harness._backend.secret_get(label="certificate-0")
        self.assertEqual(secret["certificate"], CERTIFICATE)
        self.assertEqual(secret["ca-certificate"], CA)
        self.assertEqual(
            secret["chain"],
            json.dumps(chain),
        )
        self.assertEqual(
            secret["csr"],
            CSR,
        )

    def test_given_csrs_match_when_on_certificate_available_then_status_is_active(self):
        chain = ["whatever cert 1", "whatever cert 2"]
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(label="csr-0", content={"csr": CSR})

        self.harness.charm._on_certificate_available(
            event=Mock(
                certificate=CERTIFICATE,
                ca=CA,
                chain=chain,
                certificate_signing_request=CSR,
            )
        )
        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("Certificate is available"),
        )

    def test_given_certificate_already_stored_when_on_certificate_available_then_certificate_is_overwritten(  # noqa: E501
        self,
    ):
        chain = ["whatever cert 1", "whatever cert 2"]
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(label="csr-0", content={"csr": CSR})
        self.harness._backend.secret_add(
            label="certificate-0",
            content={
                "certificate": "old certificate",
                "ca-certificate": "old ca certificate",
                "chain": "old chain",
            },
        )

        self.harness.charm._on_certificate_available(
            event=Mock(
                certificate=CERTIFICATE,
                ca=CA,
                chain=chain,
                certificate_signing_request=CSR,
            )
        )

        secret = self.harness._backend.secret_get(label="certificate-0")
        self.assertEqual(secret["certificate"], CERTIFICATE)
        self.assertEqual(secret["ca-certificate"], CA)
        self.assertEqual(
            secret["chain"],
            json.dumps(chain),
        )
        self.assertEqual(
            secret["csr"],
            CSR,
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
        chain = ["whatever chain"]
        event = Mock()
        self.harness._backend.secret_add(
            label="certificate-0",
            content={
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
                "chain": json.dumps(chain),
                "csr": CSR,
            },
        )

        self.harness.charm._on_get_certificate_action(event=event)

        event.set_results.assert_called_with(
            {
                "certificate": CERTIFICATE,
                "ca-certificate": CA,
                "chain": chain,
                "csr": CSR,
            }
        )

    def test_given_certificate_is_stored_when_on_certificates_relation_broken_then_certificate_secret_is_removed(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(
            label="certificate-0",
            content={
                "certificate": "whatever",
                "ca-certificate": CA,
                "chain": "whatever chain",
            },
        )

        self.harness.charm._on_certificates_relation_broken(event=Mock())

        with pytest.raises(SecretNotFoundError):
            self.harness._backend.secret_get(label="certificate-0")

    @patch("charm.generate_csr")
    def test_given_csr_stored_when_relation_joined_then_csr_not_generated_again(
        self, patch_generate_csr
    ):
        self.harness.set_leader(is_leader=True)
        self.harness._backend.secret_add(label="csr-0", content={"csr": CSR})
        self.add_secret_for_private_key(
            private_key=PRIVATE_KEY, private_key_password=PRIVATE_KEY_PASSWORD
        )
        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.assertEqual(self.harness._backend.secret_get(label="csr-0")["csr"], CSR)
        patch_generate_csr.assert_not_called()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation"  # noqa: E501, W505
    )
    def test_given_certificate_stored_when_relation_joined_then_certificate_not_requested_again(
        self,
        patch_request_certificate_creation,
    ):
        self.harness.set_leader(is_leader=True)
        chain = ["whatever cert 1", "whatever cert 2"]
        self.harness._backend.secret_add(label="csr-0", content={"csr": CSR})

        relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="certificates-provider"
        )

        self.harness.charm._on_certificate_available(
            event=Mock(
                certificate=CERTIFICATE,
                ca=CA,
                chain=chain,
                certificate_signing_request=CSR,
            )
        )
        self.add_secret_for_private_key(
            private_key=PRIVATE_KEY, private_key_password=PRIVATE_KEY_PASSWORD
        )

        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="certificates-provider/0"
        )

        self.assertEqual(
            self.harness.model.unit.status,
            ActiveStatus("Certificate is available"),
        )
        patch_request_certificate_creation.assert_not_called()
