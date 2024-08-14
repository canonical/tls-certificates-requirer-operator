# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
import scenario
from charm import TLSRequirerCharm
from ops.model import ActiveStatus
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


class TestCharmUnitMode:
    @pytest.fixture(autouse=True)
    def private_key_fixture(self):
        self.private_key = generate_private_key()

    @pytest.fixture(autouse=True)
    def csr_fixture(self, private_key_fixture):
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

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=TLSRequirerCharm,
        )

    def test_given_certificate_request_is_made_when_evaluate_status_then_status_is_active(
        self,
    ):
        csr_secret = scenario.Secret(
            id="1",
            contents={0: {"csr": self.csr}},
            owner="unit",
            revision=0,
            label="csr-0",
        )

        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )
        state_in = scenario.State(
            config={
                "mode": "unit",
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            },
            relations=[certificates_relation],
            secrets=[csr_secret],
        )

        state_out = self.ctx.run(event="collect_unit_status", state=state_in)

        assert state_out.unit_status == ActiveStatus("Waiting for unit certificate")

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_csrs_match_when_on_certificate_available_then_certificate_is_stored(
        self,
        patch_get_assigned_certificate,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        state_in = scenario.State(
            config={
                "mode": "unit",
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            },
            relations=[certificates_relation],
            secrets=[],
        )

        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=certificates_relation.relation_id,
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )

        state_out = self.ctx.run(event="update_status", state=state_in)

        assert state_out.secrets[0].label == f"tls-certificates-requirer-0.{state_in.model.name}"
        assert state_out.secrets[0].contents == {
            0: {"certificate": CERTIFICATE, "ca-certificate": CA, "csr": self.csr}
        }

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_stored_when_on_evaluate_status_then_status_is_active(
        self,
        patch_get_assigned_certificate,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=certificates_relation.relation_id,
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
                revoked=False,
            ),
            PrivateKey.from_string(self.private_key),
        )
        certificate_secret = scenario.Secret(
            id="1",
            contents={0: {"certificate": CERTIFICATE, "ca-certificate": CA}},
            owner="unit",
            revision=0,
            label="certificate-0",
        )

        state_in = scenario.State(
            config={
                "mode": "unit",
                "common_name": COMMON_NAME,
                "sans_dns": COMMON_NAME,
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            },
            relations=[certificates_relation],
            secrets=[certificate_secret],
        )

        state_out = self.ctx.run(event="update_status", state=state_in)

        assert state_out.unit_status == ActiveStatus("Unit certificate is available")

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_already_stored_when_new_matching_certificate_available_then_certificate_is_overwritten(  # noqa: E501
        self, patch_get_assigned_certificate
    ):
        model_name = "abc"
        certificate_secret = scenario.Secret(
            id="1",
            contents={0: {"certificate": CERTIFICATE, "ca-certificate": CA}},
            owner="unit",
            revision=0,
            label=f"tls-certificates-requirer-0.{model_name}",
        )

        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        state_in = scenario.State(
            model=scenario.Model(name=model_name),
            config={
                "mode": "unit",
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            },
            relations=[certificates_relation],
            secrets=[certificate_secret],
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
                relation_id=certificates_relation.relation_id,
                certificate=Certificate.from_string(new_certificate),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )

        state_out = self.ctx.run(event="update_status", state=state_in)

        assert state_out.secrets[0].contents[1] == {
            "certificate": new_certificate,
            "ca-certificate": CA,
            "csr": self.csr,
        }

    def test_given_certificate_is_not_stored_when_on_get_certificate_action_then_event_fails(self):
        state_in = scenario.State(
            config={
                "mode": "unit",
            },
            leader=True,
            secrets=[],
        )

        action_output = self.ctx.run_action(action="get-certificate", state=state_in)

        assert action_output.success is False

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_is_stored_when_on_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        patch_get_assigned_certificate,
    ):
        model_name = "abc"
        certificate_secret = scenario.Secret(
            id="1",
            contents={0: {"certificate": CERTIFICATE, "ca-certificate": CA, "csr": self.csr}},
            owner="unit",
            revision=0,
            label=f"tls-certificates-requirer-0.{model_name}",
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=certificates_relation.relation_id,
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )

        state_in = scenario.State(
            model=scenario.Model(name=model_name),
            config={
                "mode": "unit",
            },
            relations=[certificates_relation],
            leader=True,
            secrets=[certificate_secret],
        )

        action_output = self.ctx.run_action(action="get-certificate", state=state_in)

        assert action_output.success is True
        assert action_output.results == {
            "certificate": CERTIFICATE,
            "ca-certificate": CA,
            "csr": self.csr,
        }

    def test_given_certificate_is_stored_when_on_certificates_relation_broken_then_certificate_secret_is_removed(  # noqa: E501
        self,
    ):
        model_name = "abc"
        certificate_secret = scenario.Secret(
            id="2",
            contents={0: {"certificate": "whatever", "ca-certificate": CA}},
            owner="unit",
            revision=0,
            label=f"tls-certificates-requirer-0.{model_name}",
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        state_in = scenario.State(
            model=scenario.Model(name=model_name),
            config={
                "mode": "unit",
            },
            relations=[certificates_relation],
            secrets=[certificate_secret],
        )

        state_out = self.ctx.run(event=certificates_relation.broken_event, state=state_in)

        assert state_out.secrets[0].contents == {}


class TestCharmAppMode:
    @pytest.fixture(autouse=True)
    def private_key_fixture(self):
        self.private_key = generate_private_key()

    @pytest.fixture(autouse=True)
    def csr_fixture(self, private_key_fixture):
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

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=TLSRequirerCharm,
        )

    def test_given_certificate_request_is_made_when_evaluate_status_then_status_is_active(
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        state_in = scenario.State(
            config={
                "mode": "app",
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            },
            relations=[certificates_relation],
            leader=True,
            secrets=[],
        )

        state_out = self.ctx.run(event="collect_unit_status", state=state_in)

        assert state_out.unit_status == ActiveStatus("Waiting for app certificate")

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_csrs_match_when_on_certificate_available_then_certificate_is_stored(
        self,
        patch_get_assigned_certificate,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=certificates_relation.relation_id,
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )

        state_in = scenario.State(
            config={
                "mode": "app",
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            },
            relations=[certificates_relation],
            leader=True,
            secrets=[],
        )

        state_out = self.ctx.run(event="update_status", state=state_in)

        assert state_out.secrets[0].label == f"tls-certificates-requirer.{state_in.model.name}"
        assert state_out.secrets[0].contents == {
            0: {"certificate": CERTIFICATE, "ca-certificate": CA, "csr": self.csr}
        }

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_stored_when_on_evaluate_status_then_status_is_active(
        self,
        patch_get_assigned_certificate,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )
        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=certificates_relation.relation_id,
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )

        state_in = scenario.State(
            config={
                "mode": "app",
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            },
            relations=[certificates_relation],
            leader=True,
            secrets=[],
        )

        state_out = self.ctx.run(event="update_status", state=state_in)

        assert state_out.unit_status == ActiveStatus("App certificate is available")

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_already_stored_when_new_matching_certificate_available_then_certificate_is_overwritten(  # noqa: E501
        self, patch_get_assigned_certificate
    ):
        model_name = "abc"
        certificate_secret = scenario.Secret(
            id="1",
            contents={0: {"certificate": CERTIFICATE, "ca-certificate": CA}},
            owner="app",
            revision=0,
            label=f"tls-certificates-requirer.{model_name}",
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        state_in = scenario.State(
            model=scenario.Model(name=model_name),
            config={
                "mode": "app",
                "organization_name": ORGANIZATION_NAME,
                "email_address": EMAIL_ADDRESS,
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
            },
            relations=[certificates_relation],
            leader=True,
            secrets=[certificate_secret],
        )

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
                relation_id=certificates_relation.relation_id,
                certificate=Certificate.from_string(new_certificate),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )

        state_out = self.ctx.run(event="update_status", state=state_in)

        assert state_out.secrets[0].contents[1] == {
            "certificate": new_certificate,
            "ca-certificate": CA,
            "csr": self.csr,
        }

    def test_given_certificate_is_not_stored_when_on_get_certificate_action_then_event_fails(self):
        state_in = scenario.State(
            config={
                "mode": "app",
            },
            leader=True,
            secrets=[],
        )

        action_output = self.ctx.run_action(action="get-certificate", state=state_in)

        assert action_output.success is False

    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"  # noqa: E501, W505
    )
    def test_given_certificate_is_stored_when_on_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        patch_get_assigned_certificate,
    ):
        model_name = "abc"
        certificate_secret = scenario.Secret(
            id="2",
            contents={0: {"certificate": CERTIFICATE, "ca-certificate": CA, "csr": self.csr}},
            owner="app",
            revision=0,
            label=f"tls-certificates-requirer.{model_name}",
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        patch_get_assigned_certificate.return_value = (
            ProviderCertificate(
                relation_id=certificates_relation.relation_id,
                certificate=Certificate.from_string(CERTIFICATE),
                ca=Certificate.from_string(CA),
                chain=[Certificate.from_string(CA)],
                revoked=False,
                certificate_signing_request=CertificateSigningRequest.from_string(self.csr),
            ),
            PrivateKey.from_string(self.private_key),
        )

        state_in = scenario.State(
            model=scenario.Model(name=model_name),
            config={
                "mode": "app",
            },
            relations=[certificates_relation],
            leader=True,
            secrets=[certificate_secret],
        )

        action_output = self.ctx.run_action(action="get-certificate", state=state_in)

        assert action_output.success is True
        assert action_output.results == {
            "certificate": CERTIFICATE,
            "ca-certificate": CA,
            "csr": self.csr,
        }

    def test_given_certificate_is_stored_when_on_certificates_relation_broken_then_certificate_secret_is_removed(  # noqa: E501
        self,
    ):
        model_name = "abc"
        certificate_secret = scenario.Secret(
            id="2",
            contents={0: {"certificate": "whatever", "ca-certificate": CA}},
            owner="app",
            revision=0,
            label=f"tls-certificates-requirer.{model_name}",
        )
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
            remote_app_name="certificate-provider",
        )

        state_in = scenario.State(
            model=scenario.Model(name=model_name),
            config={
                "mode": "app",
            },
            relations=[certificates_relation],
            leader=True,
            secrets=[certificate_secret],
        )

        state_out = self.ctx.run(event=certificates_relation.broken_event, state=state_in)

        assert state_out.secrets[0].contents == {}
