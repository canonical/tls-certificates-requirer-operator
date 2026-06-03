#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import platform
import time
from pathlib import Path

import jubilant
import pytest
from certificates import Certificate, CertificateAttributes

logger = logging.getLogger(__name__)

SELF_SIGNED_CERTIFICATES_CHARM_NAME = "self-signed-certificates"

NUM_UNITS = 3

ARCH = "arm64" if platform.machine() == "aarch64" else "amd64"


def wait_for_certificate_available(
    juju: jubilant.Juju,
    unit_name: str,
    expected_certificate_attributes: CertificateAttributes,
) -> None:
    """Run the `get-certificate` action.

    Runs until the action returns a certificate with the expected attributes.
    If the action does not return certificates within 60 seconds, a TimeoutError is raised.

    Args:
        juju: The Juju instance.
        unit_name: The name of the unit to run the action on.
        expected_certificate_attributes: The expected attributes of the certificate.
    """
    start_time = time.time()
    while time.time() - start_time < 60:
        try:
            task = juju.run(unit_name, "get-certificate", wait=30)
        except jubilant.TaskError:
            logger.info("Action failed")
            time.sleep(1)
            continue
        certificates = task.results.get("certificates", None)
        if not certificates:
            logger.info("Certificates are not available")
            time.sleep(1)
            continue
        certificate_list = json.loads(certificates)
        certs_obj = [Certificate(certificate["certificate"]) for certificate in certificate_list]
        for cert_obj in certs_obj:
            if cert_obj.has_attributes(certificate_attributes=expected_certificate_attributes):
                logger.info("Certificate has the expected attributes")
                return
        logger.info("Certificate does not have the expected attributes")
        time.sleep(1)
    raise TimeoutError("Timed out waiting for certificate")


def get_leader_unit_name(juju: jubilant.Juju, app_name: str) -> str:
    """Return the leader unit name for the given application."""
    status = juju.status()
    for unit_name, unit_status in status.apps[app_name].units.items():
        if unit_status.leader:
            return unit_name
    raise RuntimeError(f"Leader unit for `{app_name}` not found.")


class TestTLSRequirer:
    APP_NAME = "tls-requirer"
    SELF_SIGNED_CERTIFICATES_APP_NAME = "self-signed-certificates"
    SELF_SIGNED_CERTIFICATES_AMD64_REVISION = 317
    SELF_SIGNED_CERTIFICATES_ARM64_REVISION = 262

    @pytest.fixture(scope="module")
    def deploy(self, juju: jubilant.Juju, request: pytest.FixtureRequest):
        """Deploy charm under test."""
        charm = Path(str(request.config.getoption("--charm_path"))).resolve()
        logger.info("Deploying charms for architecture: %s", ARCH)
        revision = (
            self.SELF_SIGNED_CERTIFICATES_ARM64_REVISION
            if ARCH == "arm64"
            else self.SELF_SIGNED_CERTIFICATES_AMD64_REVISION
        )
        juju.model_constraints({"arch": ARCH})
        juju.deploy(
            charm,
            self.APP_NAME,
            config={
                "mode": "unit",
                "organization_name": "Canonical",
                "country_name": "GB",
                "state_or_province_name": "London",
                "locality_name": "London",
            },
            base="ubuntu@22.04",
            num_units=NUM_UNITS,
            constraints={"arch": ARCH},
        )
        juju.deploy(
            SELF_SIGNED_CERTIFICATES_CHARM_NAME,
            self.SELF_SIGNED_CERTIFICATES_APP_NAME,
            channel="1/stable",
            revision=revision,
            constraints={"arch": ARCH},
        )
        juju.model_config({"update-status-hook-interval": "10s"})
        yield

    @pytest.mark.juju_setup
    def test_given_charm_is_built_when_deployed_then_status_is_active(
        self,
        juju: jubilant.Juju,
        deploy: None,
    ):
        juju.wait(
            lambda status: jubilant.all_active(status, self.APP_NAME),
            timeout=1000,
        )

    @pytest.mark.juju_setup
    def test_given_self_signed_certificates_deployed_when_integrate_then_status_is_active(
        self,
        juju: jubilant.Juju,
        deploy: None,
    ):
        juju.wait(
            lambda status: jubilant.all_active(status, self.SELF_SIGNED_CERTIFICATES_APP_NAME),
            timeout=1000,
        )
        juju.integrate(
            f"{self.SELF_SIGNED_CERTIFICATES_APP_NAME}:certificates",
            f"{self.APP_NAME}",
        )
        juju.wait(
            lambda status: jubilant.all_active(status, self.APP_NAME),
            timeout=1000,
        )

    def test_given_self_signed_certificates_is_related_when_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        juju: jubilant.Juju,
        deploy: None,
    ):
        for unit in range(NUM_UNITS):
            expected_certificate_attributes = CertificateAttributes(
                common_name=f"cert-0.unit-{unit}.{self.APP_NAME}.{juju.model}",
                email_address=None,
                organization_name="Canonical",
                country_name="GB",
                state_or_province_name="London",
                locality_name="London",
            )
            wait_for_certificate_available(
                juju=juju,
                unit_name=f"{self.APP_NAME}/{unit}",
                expected_certificate_attributes=expected_certificate_attributes,
            )

    def test_given_new_configuration_when_config_changed_then_new_certificate_is_requested(
        self, juju: jubilant.Juju, deploy: None
    ):
        juju.wait(
            lambda status: jubilant.all_active(status, self.APP_NAME),
            timeout=1000,
        )

        juju.config(
            self.APP_NAME,
            {
                "mode": "unit",
                "organization_name": "Ubuntu",
                "email_address": "pizza@canonical.com",
                "country_name": "CA",
                "state_or_province_name": "Quebec",
                "locality_name": "Montreal",
            },
        )

        for unit in range(NUM_UNITS):
            expected_certificate_attributes = CertificateAttributes(
                common_name=f"cert-0.unit-{unit}.{self.APP_NAME}.{juju.model}",
                email_address="pizza@canonical.com",
                organization_name="Ubuntu",
                country_name="CA",
                state_or_province_name="Quebec",
                locality_name="Montreal",
            )
            wait_for_certificate_available(
                juju=juju,
                unit_name=f"{self.APP_NAME}/{unit}",
                expected_certificate_attributes=expected_certificate_attributes,
            )

    def test_given_app_mode_when_config_changed_then_new_certificate_is_requested(
        self, juju: jubilant.Juju, deploy: None
    ):
        juju.wait(
            lambda status: jubilant.all_active(status, self.APP_NAME),
            timeout=1000,
        )

        juju.config(
            self.APP_NAME,
            {
                "mode": "app",
                "organization_name": "Ubuntu",
                "email_address": "pizza@canonical.com",
                "country_name": "CA",
                "state_or_province_name": "Quebec",
                "locality_name": "Montreal",
                "is_ca": "true",
            },
        )

        leader_unit_name = get_leader_unit_name(juju, self.APP_NAME)
        expected_certificate_attributes = CertificateAttributes(
            common_name=f"cert-0.{self.APP_NAME}.{juju.model}",
            email_address="pizza@canonical.com",
            organization_name="Ubuntu",
            country_name="CA",
            state_or_province_name="Quebec",
            locality_name="Montreal",
            is_ca=True,
        )
        wait_for_certificate_available(
            juju=juju,
            unit_name=leader_unit_name,
            expected_certificate_attributes=expected_certificate_attributes,
        )

    def test_given_certificate_transfer_relation_when_get_trusted_ca_certificates_action_then_bundle_is_returned(  # noqa: E501
        self, juju: jubilant.Juju, deploy: None
    ):
        juju.integrate(
            f"{self.APP_NAME}:certificate_transfer",
            f"{self.SELF_SIGNED_CERTIFICATES_APP_NAME}:send-ca-cert",
        )
        juju.wait(
            lambda status: jubilant.all_agents_idle(status, self.APP_NAME),
            timeout=1000,
        )

        leader_unit_name = get_leader_unit_name(juju, self.APP_NAME)
        task = juju.run(leader_unit_name, "get-trusted-ca-certificates")

        assert task.success

        ca_bundle = task.results.get("ca-certificates")
        assert ca_bundle
        assert "-----BEGIN CERTIFICATE-----" in ca_bundle
        assert "-----END CERTIFICATE-----" in ca_bundle

        cert = Certificate(ca_bundle)
        assert cert.common_name
