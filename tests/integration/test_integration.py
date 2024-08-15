#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Optional

import pytest
from certificates import Certificate
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

SELF_SIGNED_CERTIFICATES_CHARM_NAME = "self-signed-certificates"

NUM_UNITS = 3


async def wait_for_certificates_available(
    ops_test: OpsTest,
    unit_name: str,
    email_address: Optional[str] = None,
    organization_name: Optional[str] = None,
    country_name: Optional[str] = None,
    state_or_province_name: Optional[str] = None,
    locality_name: Optional[str] = None,
):
    """Run the `get-certificate` action until it returns certificates.

    If the action does not return certificates within 60 seconds, a TimeoutError is raised.
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
        if action_output["return-code"] != 0:
            logger.info("Action failed")
            time.sleep(1)
            continue
        certificates = action_output.get("certificates", None)
        if not certificates:
            logger.info("Certificates are not available")
            time.sleep(1)
            continue
        certificate_list = json.loads(certificates)
        certs_obj = [Certificate(certificate["certificate"]) for certificate in certificate_list]
        for cert_obj in certs_obj:
            if not cert_obj.has_attributes(
                email_address=email_address,
                organization_name=organization_name,
                country_name=country_name,
                state_or_province_name=state_or_province_name,
                locality_name=locality_name,
            ):
                logger.info("Certificate does not have the expected attributes")
                time.sleep(1)
                continue
        return
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
            channel="edge",
        )
        await ops_test.model.set_config(config={"update-status-hook-interval": "10s"})
        deployed_apps = [self.APP_NAME, self.SELF_SIGNED_CERTIFICATES_APP_NAME]
        yield
        remove_coroutines = [
            ops_test.model.remove_application(
                app_name=app_name,
                destroy_storage=True,
            )
            for app_name in deployed_apps
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
            wait_for_exact_units=NUM_UNITS,
        )

    async def test_given_self_signed_certificates_deployed_when_integrate_then_status_is_active(
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
            relation2=f"{self.APP_NAME}",
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
            await wait_for_certificates_available(
                ops_test=ops_test,
                unit_name=f"{self.APP_NAME}/{unit}",
                email_address=None,
                organization_name="Canonical",
                country_name="GB",
                state_or_province_name="London",
                locality_name="London",
            )

    async def test_given_new_configuration_when_config_changed_then_new_certificate_is_requested(
        self, ops_test, deploy
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[self.APP_NAME],
            status="active",
            timeout=1000,
        )

        tls_requirer_app = ops_test.model.applications[self.APP_NAME]

        await tls_requirer_app.set_config(
            {
                "organization_name": "Ubuntu",
                "email_address": "pizza@canonical.com",
                "country_name": "CA",
                "state_or_province_name": "Quebec",
                "locality_name": "Montreal",
            }
        )

        leader_unit = await get_leader_unit(ops_test.model, self.APP_NAME)
        await wait_for_certificates_available(
            ops_test=ops_test,
            unit_name=leader_unit.name,
            email_address="pizza@canonical.com",
            organization_name="Ubuntu",
            country_name="CA",
            state_or_province_name="Quebec",
            locality_name="Montreal",
        )


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
            channel="edge",
        )
        deployed_apps = [self.APP_NAME, self.SELF_SIGNED_CERTIFICATES_APP_NAME]
        yield
        remove_coroutines = [
            ops_test.model.remove_application(
                app_name=app_name,
                destroy_storage=True,
                block_until_done=True,
            )
            for app_name in deployed_apps
        ]
        await asyncio.gather(*remove_coroutines)

    @pytest.mark.abort_on_fail
    async def test_given_charm_is_built_when_deployed_then_status_is_idle(
        self,
        ops_test: OpsTest,
        deploy,
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[self.APP_NAME],
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
            relation2=f"{self.APP_NAME}",
        )
        await ops_test.model.wait_for_idle(
            apps=[self.APP_NAME],
            timeout=1000,
        )

    async def test_given_self_signed_certificates_is_related_when_get_certificate_action_then_certificate_is_returned(  # noqa: E501
        self,
        ops_test,
        deploy,
    ):
        leader_unit = await get_leader_unit(ops_test.model, self.APP_NAME)
        await wait_for_certificates_available(
            ops_test=ops_test,
            unit_name=leader_unit.name,
            email_address=None,
            organization_name="Canonical",
            country_name="GB",
            state_or_province_name="London",
            locality_name="London",
        )

    async def test_given_new_configuration_when_config_changed_then_new_certificate_is_requested(
        self, ops_test, deploy
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[self.APP_NAME],
            timeout=1000,
        )

        tls_requirer_app = ops_test.model.applications[self.APP_NAME]

        await tls_requirer_app.set_config(
            {
                "organization_name": "Ubuntu",
                "email_address": "ubuntu@pizza.com",
                "country_name": "CA",
                "state_or_province_name": "Quebec",
                "locality_name": "Montreal",
            }
        )

        leader_unit = await get_leader_unit(ops_test.model, self.APP_NAME)

        await wait_for_certificates_available(
            ops_test=ops_test,
            unit_name=leader_unit.name,
            email_address="ubuntu@pizza.com",
            organization_name="Ubuntu",
            country_name="CA",
            state_or_province_name="Quebec",
            locality_name="Montreal",
        )
