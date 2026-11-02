---
page_title: "freeipa_service_principal_alias Resource - freeipa"
description: |-
  Associates an additional Kerberos principal alias with an existing FreeIPA service.
---

# freeipa_service_principal_alias (Resource)

Associates an additional Kerberos principal alias with an existing FreeIPA service. The canonical service remains independently owned; this resource manages only the alias association.

## Example Usage

```terraform
resource "freeipa_service" "router" {
  principal      = "HTTP/router.central.example.test"
  force          = true
  skip_host_check = true
}

resource "freeipa_service_principal_alias" "etna" {
  principal = freeipa_service.router.principal
  alias     = "HTTP/etna.host.example.test"
}
```

## Import Usage

```terraform
import {
  to = freeipa_service_principal_alias.etna
  id = "HTTP/router.central.example.test|HTTP/etna.host.example.test"
}
```

## Schema

### Required

- `principal` (String) Canonical FreeIPA service principal.
- `alias` (String) Additional principal alias to associate with the canonical service.

### Read-Only

- `id` (String) ID of the association.
