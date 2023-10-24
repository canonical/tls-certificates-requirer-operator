#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
SELF_SIGNED_CERTIFICATES_CHARM_NAME = "self-signed-certificates"


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it."""
    charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(  # type: ignore[union-attr]
        charm,
        application_name=APP_NAME,
        series="jammy",
        trust=True,
        num_units=3,
    )


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_blocked(
    ops_test: OpsTest,
    build_and_deploy,
):
    await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
        apps=[APP_NAME],
        status="blocked",
        timeout=1000,
    )


async def test_given_self_signed_certificates_is_related_when_deployed_then_status_is_active(  # noqa: E501
    ops_test: OpsTest,
    build_and_deploy,
):
    await ops_test.model.deploy(  # type: ignore[union-attr]
        SELF_SIGNED_CERTIFICATES_CHARM_NAME,
        application_name=SELF_SIGNED_CERTIFICATES_CHARM_NAME,
        channel="edge",
    )
    await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
        apps=[SELF_SIGNED_CERTIFICATES_CHARM_NAME],
        status="active",
        timeout=1000,
    )
    await ops_test.model.add_relation(  # type: ignore[union-attr]
        relation1=f"{SELF_SIGNED_CERTIFICATES_CHARM_NAME}:certificates", relation2=f"{APP_NAME}"
    )
    await ops_test.model.wait_for_idle(  # type: ignore[union-attr]
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )
