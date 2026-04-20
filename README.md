# TLS Certificates Requirer Operator

[![CharmHub Badge](https://charmhub.io/tls-certificates-requirer/badge.svg)](https://charmhub.io/tls-certificates-requirer)

Charm that requests X.509 certificates using the `tls-certificates` interface.

It uses the user-provided `subject` configuration to generate a certificate signing request
(CSR) that will be inserted into its unit relation data as soon as the `tls-certificates` relation
is created. In return, the certificate provider should use this CSR, generate a certificate, 
and provide it back into their application relation data.

This charm is useful when developing and testing certificate providers.

For more information, including guides, integrations, and configuration options, read the [TLS Certificates Requirer documentation](https://charmhub.io/tls-certificates-requirer).

## Project & Community

TLS Certificates Requirer Operator is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

- To contribute to the code Please see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines and best practices.
- Raise software issues or feature requests in [GitHub](https://github.com/canonical/tls-certificates-requirer-operator/issues)
- Meet the community and chat with us on [Matrix](https://matrix.to/#/#tls:ubuntu.com)
