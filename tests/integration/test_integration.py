#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import time
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
SELF_SIGNED_CERTIFICATES_CHARM_NAME = "self-signed-certificates"

NUM_UNITS = 3


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it."""
    assert ops_test.model
    charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(
        charm,
        application_name=APP_NAME,
        series="jammy",
        trust=True,
        num_units=NUM_UNITS,
    )


async def wait_for_certificate_available(ops_test: OpsTest, unit_name: str) -> dict:
    """Runs the `get-certificate` action until it returns a certificate.

    If the action does not return a certificate within 60 seconds, a TimeoutError is raised.
    """
    assert ops_test.model
    start_time = time.time()
    while time.time() - start_time < 60:
        tls_requirer_unit = ops_test.model.units[unit_name]
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


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_active(
    ops_test: OpsTest,
    build_and_deploy,
):
    assert ops_test.model
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )


async def test_given_self_signed_certificates_is_related_when_deployed_then_status_is_active(  # noqa: E501
    ops_test: OpsTest,
    build_and_deploy,
):
    assert ops_test.model
    await ops_test.model.deploy(
        SELF_SIGNED_CERTIFICATES_CHARM_NAME,
        application_name=SELF_SIGNED_CERTIFICATES_CHARM_NAME,
        channel="edge",
    )
    await ops_test.model.wait_for_idle(
        apps=[SELF_SIGNED_CERTIFICATES_CHARM_NAME],
        status="active",
        timeout=1000,
    )
    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_CHARM_NAME}:certificates", relation2=f"{APP_NAME}"
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )


async def test_given_self_signed_certificates_is_related_when_get_certificate_action_then_certificate_is_returned(  # noqa: E501
    ops_test,
    build_and_deploy,
):
    for unit in range(NUM_UNITS):
        action_output = await wait_for_certificate_available(
            ops_test=ops_test, unit_name=f"{APP_NAME}/{unit}"
        )

        assert action_output["certificate"] is not None
        assert action_output["ca-certificate"] is not None
        assert action_output["chain"] is not None
        assert action_output["csr"] is not None
