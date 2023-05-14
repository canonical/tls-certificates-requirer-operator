# TLS Requirer Operator

Charm that requests X.509 certificates using the `tls-certificates` interface.

It uses the user-provided `subject` configuration to generate a certificate signing request
(CSR) that will be inserted into its unit relation data as soon as the `tls-certificates` relation
is created. In return, the certificate provider should use this CSR, generate a certificate, 
and provide it back into their application relation data.

This charm is useful when developing and testing certificate providers.

## Pre-requisites

- Juju >= 3.0

## Usage

Deploy the charm and relate it to a certificate provider:

```bash
juju deploy tls-requirer-operator
juju relate tls-requirer-operator <TLS Certificates Provider>
```

Access the generated certificate:

```bash
juju run tls-requirer-operator/leader get-certificate
```

## Limitations

This charm doesn't scale up.

## Relations

- `tls-certificates`: Used for charms that require/provide TLS certificates.
