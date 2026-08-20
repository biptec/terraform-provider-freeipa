Terraform FreeIPA Provider
==========================

Tested on FreeIPA version 4.13.1.

This repository is the BIPTEC downstream of `rework-space-com/freeipa`. It keeps
upstream behavior by default and adds Kerberos/keytab provider authentication
and a caller-supplied write-only host enrollment password.

Requirements
------------

- [Terraform](https://www.terraform.io/downloads.html) 1.0+ for existing provider features.
- Terraform or OpenTofu 1.11+ when using `freeipa_host.userpassword_wo`.
- [Go](https://golang.org/doc/install) 1.25.11+ to build the provider plugin.

Authentication
--------------

### Username/password

The existing authentication mode remains supported and unchanged:

```hcl
provider "freeipa" {
  host     = "ipa.example.test"
  username = "admin"
  password = var.freeipa_password
}
```

The same values can be supplied with `FREEIPA_HOST`, `FREEIPA_USERNAME`, and
`FREEIPA_PASSWORD`.

### Kerberos/keytab

Automation can authenticate without a long-lived FreeIPA password:

```hcl
provider "freeipa" {
  host               = "ipa.example.test"
  kerberos_principal = "terraform/runner@EXAMPLE.TEST"
  krb5_conf_path     = "/etc/krb5.conf"
  keytab_path        = "/run/secrets/freeipa.keytab"
}
```

Supported environment variables are `FREEIPA_KERBEROS_PRINCIPAL`,
`FREEIPA_KERBEROS_REALM`, `FREEIPA_KRB5_CONF`, and `FREEIPA_KEYTAB`. A full
principal containing `@REALM` is accepted, in which case `kerberos_realm` is
optional.

If any Kerberos setting is configured, Kerberos mode is selected. When both
password and Kerberos credentials are present, Kerberos takes precedence. A
Kerberos failure is returned as an error and never falls back silently to the
password mode.

Treat keytabs as secrets. Keep them outside the repository, use restrictive
permissions such as `0600`, and inject them through the runner's secret store.
The provider does not log password or keytab contents.

FreeIPA uses the authenticated HTTP service for constrained delegation to its
LDAP backend. The Kerberos credentials used by the provider therefore need a
forwardable TGT. Configure `forwardable = true` in `krb5.conf` (or enforce the
equivalent Kerberos policy) for the provider principal.

Write-only host enrollment password
-----------------------------------

`freeipa_host.userpassword_wo` is intended for two-stage enrollment where an
external system generates the one-time password, Terraform/OpenTofu pre-creates
the IPA host, and the external system later enrolls with the same password.

```hcl
variable "freeipa_enrollment_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "freeipa_host" "node" {
  name                    = "node01.example.test"
  ip_address              = "192.0.2.10"
  force                   = true
  userpassword_wo         = var.freeipa_enrollment_password
  userpassword_wo_version = 1
}
```

`userpassword_wo` is both `Sensitive` and `WriteOnly`. Its value is sent to
FreeIPA for `host_add`/`host_mod` but is not persisted in Terraform/OpenTofu
state. `userpassword_wo_version` is intentionally persistent and acts as the
rotation trigger. Increment the version and supply a new password to rotate the
enrollment secret in place. Changing the version without a new write-only
password is rejected during planning; rotation never recreates the host.

The legacy `userpassword`, `random_password`, and `generated_password` behavior
is preserved for compatibility. Those legacy password paths are stateful and
should not be confused with the write-only contract.

Building The Provider
---------------------

Clone the repository, enter the provider directory, and build the provider:

```sh
cd terraform-provider-freeipa
go build -o ~/go/bin/terraform-provider-freeipa
```

## Contributing to the provider

To contribute, please read the [contribution guidelines](_about/CONTRIBUTING.md).

## Contributors

A full list of contributors is available in [OUR_CONTRIBUTORS.md](./OUR_CONTRIBUTORS.md).
We acknowledge and thank everyone who has contributed to this project.
