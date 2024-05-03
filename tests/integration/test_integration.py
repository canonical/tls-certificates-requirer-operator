#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time
from pathlib import Path

import pytest
from certificates import Certificate
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

SELF_SIGNED_CERTIFICATES_CHARM_NAME = "self-signed-certificates"

NUM_UNITS = 3


async def wait_for_certificate_available(ops_test: OpsTest, unit_name: str) -> dict:
    """Run the `get-certificate` action until it returns a certificate.

    If the action does not return a certificate within 60 seconds, a TimeoutError is raised.
    """
    assert ops_test.model
    start_time = time.time()
    while time.time() - start_time < 60:
        tls_requirer_unit = ops_test.model.units[unit_name]
        assert tls_requirer_unit
        action = await tls_requirer_unit.run_action(action_name="get-certificate")
        action_output = await ops_test.model.get_action_output(
            action_uuid=action.entity_id,
            wait=30,
        )
        logger.info("Action output: %s", action_output)
        if action_output["return-code"] == 0:
            return action_output
        time.sleep(1)
    raise TimeoutError("Timed out waiting for certificate")


async def get_leader_unit(model, application_name: str) -> Unit:
    """Return the leader unit for the given application."""
    for unit in model.units.values():
        if unit.application == application_name and await unit.is_leader_from_status():
            return unit
    raise RuntimeError(f"Leader unit for `{application_name}` not found.")


class TestTLSRequirerUnitMode:

    APP_NAME = "tls-requirer-unit"
    SELF_SIGNED_CERTIFICATES_APP_NAME = "self-signed-certificates-unit"

    @pytest.fixture(scope="module")
    async def deploy(self, ops_test: OpsTest, request):
        """Deploy charm under test."""
        assert ops_test.model
        charm = Path(request.config.getoption("--charm_path")).resolve()
        await ops_test.model.deploy(
            charm,
            config={
                "mode": "unit",
                "sans_dns": "example.com,example.org",
                "organization_name": "Canonical",
                "country_name": "GB",
                "state_or_province_name": "London",
                "locality_name": "London",
            },
            application_name=self.APP_NAME,
            series="jammy",
            num_units=NUM_UNITS,
        )
        await ops_test.model.deploy(
            SELF_SIGNED_CERTIFICATES_CHARM_NAME,
            application_name=self.SELF_SIGNED_CERTIFICATES_APP_NAME,
            channel="stable",
        )
        deployed_apps = [self.APP_NAME, self.SELF_SIGNED_CERTIFICATES_APP_NAME]
        yield
        remove_coroutines = [
            ops_test.model.remove_application(
                app_name=app_name,
                destroy_storage=True,
            ) for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_charm_is_built_when_deployed_then_status_is_active(
        self,
        ops_test: OpsTest,
        deploy,
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[self.APP_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_self_signed_certificates_deployed_when_integrate_then_status_is_active(  # noqa: E501
        self,
        ops_test: OpsTest,
        deploy,
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[self.SELF_SIGNED_CERTIFICATES_APP_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.integrate(
            relation1=f"{self.SELF_SIGNED_CERTIFICATES_APP_NAME}:certificates",
            relation2=f"{self.APP_NAME}"
        )
        await ops_test.model.wait_for_idle(
            apps=[self.APP_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_self_signed_certificates_is_related_when_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        ops_test,
        deploy,
    ):
        for unit in range(NUM_UNITS):
            action_output = await wait_for_certificate_available(
                ops_test=ops_test, unit_name=f"{self.APP_NAME}/{unit}"
            )

            assert action_output["certificate"] is not None
            assert action_output["ca-certificate"] is not None
            assert action_output["csr"] is not None

            certificate = Certificate(action_output["certificate"])

            assert certificate.organization_name == "Canonical"
            assert certificate.country_name == "GB"
            assert certificate.state_or_province_name == "London"
            assert certificate.locality_name == "London"
            assert certificate.email_address is None
            assert len(certificate.sans_dns) == 2
            assert "example.com" in certificate.sans_dns
            assert "example.org" in certificate.sans_dns


class TestTLSRequirerAppMode:

    APP_NAME = "tls-requirer-app"
    SELF_SIGNED_CERTIFICATES_APP_NAME = "self-signed-certificates-app"

    @pytest.fixture(scope="module")
    async def deploy(self, ops_test: OpsTest, request):
        """Deploy charm under test."""
        assert ops_test.model
        charm = Path(request.config.getoption("--charm_path")).resolve()
        await ops_test.model.deploy(
            charm,
            config={
                "mode": "app",
                "sans_dns": "example.com,example.org",
                "organization_name": "Canonical",
                "country_name": "GB",
                "state_or_province_name": "London",
                "locality_name": "London",
            },
            application_name=self.APP_NAME,
            series="jammy",
            num_units=NUM_UNITS,
        )
        await ops_test.model.deploy(
            SELF_SIGNED_CERTIFICATES_CHARM_NAME,
            application_name=self.SELF_SIGNED_CERTIFICATES_APP_NAME,
            channel="stable",
        )
        deployed_apps = [self.APP_NAME, self.SELF_SIGNED_CERTIFICATES_APP_NAME]
        yield
        remove_coroutines = [
            ops_test.model.remove_application(
                app_name=app_name,
                destroy_storage=True,
                block_until_done=True,
            ) for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)


    @pytest.mark.abort_on_fail
    async def test_given_charm_is_built_when_deployed_then_status_is_active(
        self,
        ops_test: OpsTest,
        deploy,
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[self.APP_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_self_signed_certificates_is_deployed_when_integrate_then_status_is_active(  # noqa: E501
        self,
        ops_test: OpsTest,
        deploy,
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[self.SELF_SIGNED_CERTIFICATES_APP_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.integrate(
            relation1=f"{self.SELF_SIGNED_CERTIFICATES_APP_NAME}:certificates",
            relation2=f"{self.APP_NAME}"
        )
        await ops_test.model.wait_for_idle(
            apps=[self.APP_NAME],
            status="active",
            timeout=1000,
        )

    async def test_given_self_signed_certificates_is_related_when_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        ops_test,
        deploy,
    ):
        leader_unit = await get_leader_unit(ops_test.model, self.APP_NAME)
        action_output = await wait_for_certificate_available(
            ops_test=ops_test, unit_name=leader_unit.name
        )

        assert action_output["certificate"] is not None
        assert action_output["ca-certificate"] is not None
        assert action_output["csr"] is not None

        certificate = Certificate(action_output["certificate"])

        assert certificate.organization_name == "Canonical"
        assert certificate.country_name == "GB"
        assert certificate.state_or_province_name == "London"
        assert certificate.locality_name == "London"
        assert certificate.email_address is None
        assert len(certificate.sans_dns) == 2
        assert "example.com" in certificate.sans_dns
        assert "example.org" in certificate.sans_dns
