---
page_title: "freeipa_service Data Source - freeipa"
description: |-
  Read FreeIPA metadata for a Kerberos service principal.
---

# freeipa_service (Data Source)

Reads an existing FreeIPA Kerberos service principal and exposes metadata needed by other provider-native resources.

## Example Usage

```terraform
data "freeipa_service" "issuer" {
  principal = "VPN/pizol.example.test"
}
```

## Schema

### Required

- `principal` (String) Canonical service principal in FreeIPA CLI/API form.

### Read-Only

- `id` (String) Service principal used as the data source identity.
- `dn` (String) LDAP distinguished name of the FreeIPA service entry.
