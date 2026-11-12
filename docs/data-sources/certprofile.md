---
page_title: "freeipa_certprofile Data Source - freeipa"
description: |-
  Read a FreeIPA certificate profile, including its complete Dogtag profile configuration.
---

# freeipa_certprofile (Data Source)

Reads an existing FreeIPA certificate profile and exposes its metadata plus the complete raw Dogtag profile configuration.

## Example Usage

```terraform
data "freeipa_certprofile" "source" {
  name = "IECUserRoles"
}
```

## Schema

### Required

- `name` (String) FreeIPA certificate profile ID.

### Read-Only

- `id` (String) Certificate profile ID.
- `description` (String) Certificate profile description.
- `store_issued` (Boolean) Whether issued certificates are stored by FreeIPA.
- `config` (String) Complete raw Dogtag profile configuration.
