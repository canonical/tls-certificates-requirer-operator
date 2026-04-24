#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for TLS certificate lifecycle scenarios.

This test module follows the guide from:
https://github.com/canonical/certificate-management-docs/pull/11
"""

import json
import logging
import time
from collections.abc import Generator
from pathlib import Path

import jubilant
import pytest

logger = logging.getLogger(__name__)

APP_NAME = "tls-requirer"
SSC_APP_NAME = "self-signed-certificates"


def _get_certificate(juju: jubilant.Juju) -> dict | None:
    """Get certificate from the charm.

    Args:
        juju: The jubilant Juju instance.

    Returns:
        The certificate dict or None if not available.
    """
    try:
        task = juju.run(f"{APP_NAME}/0", "get-certificate")
        certs = json.loads(task.results.get("certificates", "[]"))
        return certs[0] if certs else None
    except (jubilant.TaskError, json.JSONDecodeError, KeyError):
        return None


def wait_for_certificate(juju: jubilant.Juju, timeout: int = 300) -> dict:
    """Wait for a certificate to be available.

    Args:
        juju: The jubilant Juju instance.
        timeout: Maximum time to wait in seconds.

    Returns:
        The certificate dict.

    Raises:
        TimeoutError: If certificate is not available within timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cert = _get_certificate(juju)
        if cert and cert.get("certificate"):
            return cert
        time.sleep(5)
    raise TimeoutError("Timed out waiting for a certificate")


def wait_for_new_certificate(
    juju: jubilant.Juju, previous_certificate: str, timeout: int = 300
) -> dict:
    """Wait for a new certificate to be issued.

    Args:
        juju: The jubilant Juju instance.
        previous_certificate: The previous certificate PEM string.
        timeout: Maximum time to wait in seconds.

    Returns:
        The new certificate dict.

    Raises:
        TimeoutError: If new certificate is not available within timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cert = _get_certificate(juju)
        if cert and cert.get("certificate") != previous_certificate:
            return cert
        time.sleep(5)
    raise TimeoutError("Timed out waiting for a new leaf certificate")


def wait_for_new_ca(juju: jubilant.Juju, previous_ca: str, timeout: int = 300) -> dict:
    """Wait for a new CA certificate to be issued.

    Args:
        juju: The jubilant Juju instance.
        previous_ca: The previous CA certificate PEM string.
        timeout: Maximum time to wait in seconds.

    Returns:
        The certificate dict with new CA.

    Raises:
        TimeoutError: If new CA certificate is not available within timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cert = _get_certificate(juju)
        if cert and cert.get("ca-certificate") != previous_ca:
            return cert
        time.sleep(5)
    raise TimeoutError("Timed out waiting for a new CA certificate")


@pytest.fixture(scope="module")
def juju(request: pytest.FixtureRequest) -> Generator[jubilant.Juju, None, None]:
    """Set up the test module with a temporary Juju model.

    Args:
        request: The pytest fixture request.

    Yields:
        The jubilant Juju instance.
    """
    charm_path = Path(str(request.config.getoption("--charm_path"))).resolve()

    with jubilant.temp_model() as juju:
        # Short hook interval so expiry/renewal tests don't wait too long.
        juju.model_config({"update-status-hook-interval": "10s"})
        juju.deploy(
            str(charm_path),
            APP_NAME,
            config={
                "mode": "unit",
                "organization_name": "Canonical",
                "country_name": "GB",
                "state_or_province_name": "London",
                "locality_name": "London",
            },
        )
        juju.deploy(SSC_APP_NAME, channel="1/stable")
        juju.integrate(f"{SSC_APP_NAME}:certificates", f"{APP_NAME}:certificates")
        juju.wait(
            lambda status: jubilant.all_active(status, APP_NAME, SSC_APP_NAME),
            error=jubilant.any_error,
        )
        yield juju

        if request.session.testsfailed:
            print(juju.debug_log(limit=1000), end="")


def test_given_charms_are_integrated_then_certificate_is_received(
    juju: jubilant.Juju,
) -> None:
    """Test that certificate is received after integration.

    Args:
        juju: The jubilant Juju instance.
    """
    cert = wait_for_certificate(juju)

    assert "-----BEGIN CERTIFICATE-----" in cert["certificate"]
    assert "-----BEGIN CERTIFICATE-----" in cert["ca-certificate"]


def test_given_config_changed_then_new_certificate_is_requested(
    juju: jubilant.Juju,
) -> None:
    """Test that certificate is re-requested when config changes.

    Args:
        juju: The jubilant Juju instance.
    """
    initial = wait_for_certificate(juju)

    juju.config(APP_NAME, {"sans_dns": "new.example.com"})
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME), error=jubilant.any_error)

    new = wait_for_new_certificate(juju, initial["certificate"])

    assert new["certificate"] != initial["certificate"]


def test_given_certificate_expires_then_it_is_renewed(juju: jubilant.Juju) -> None:
    """Test that an expiring certificate is renewed.

    Args:
        juju: The jubilant Juju instance.
    """
    # Issue 1-minute certificates; CA stays valid for 3 minutes.
    juju.config(SSC_APP_NAME, {"certificate-validity": "1m", "root-ca-validity": "3m"})
    juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME, SSC_APP_NAME),
        error=jubilant.any_error,
    )

    initial = wait_for_certificate(juju)

    # Wait just past the 1-minute certificate expiry.
    time.sleep(70)

    renewed = wait_for_new_certificate(juju, initial["certificate"])

    assert renewed["certificate"] != initial["certificate"]
    # The CA must not have changed — only the leaf certificate was renewed.
    assert renewed["ca-certificate"] == initial["ca-certificate"]


def test_given_ca_config_changed_then_new_ca_issues_certificate(
    juju: jubilant.Juju,
) -> None:
    """Test that CA config change causes a new CA to be used.

    Args:
        juju: The jubilant Juju instance.
    """
    initial = wait_for_certificate(juju)

    juju.config(SSC_APP_NAME, {"ca-common-name": "new-test-ca.example.com"})
    juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME, SSC_APP_NAME),
        error=jubilant.any_error,
    )

    new = wait_for_new_ca(juju, initial["ca-certificate"])

    assert new["ca-certificate"] != initial["ca-certificate"]
    assert new["certificate"] != initial["certificate"]


def test_given_requirer_private_key_rotated_then_certificate_is_reissued(
    juju: jubilant.Juju,
) -> None:
    """Test that rotating requirer's private key re-issues certificate.

    Args:
        juju: The jubilant Juju instance.
    """
    initial = wait_for_certificate(juju)

    juju.run(f"{APP_NAME}/0", "rotate-private-key")
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME), error=jubilant.any_error)

    new = wait_for_new_certificate(juju, initial["certificate"])

    assert new["certificate"] != initial["certificate"]


def test_given_ca_private_key_rotated_then_certificates_are_reissued(
    juju: jubilant.Juju,
) -> None:
    """Test that rotating CA's private key re-issues all certificates.

    Args:
        juju: The jubilant Juju instance.
    """
    initial = wait_for_certificate(juju)

    juju.run(f"{SSC_APP_NAME}/0", "rotate-private-key")
    juju.wait(
        lambda status: jubilant.all_active(status, APP_NAME, SSC_APP_NAME),
        error=jubilant.any_error,
    )

    new = wait_for_new_ca(juju, initial["ca-certificate"])

    assert new["ca-certificate"] != initial["ca-certificate"]
    assert new["certificate"] != initial["certificate"]
