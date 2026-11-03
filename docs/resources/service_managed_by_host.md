---
page_title: "freeipa_service_managed_by_host Resource - freeipa"
description: |-
  Associates one FreeIPA host with an existing service's managedBy membership.
---

# freeipa_service_managed_by_host (Resource)

Associates one FreeIPA host with an existing service's `managedBy` membership. Multiple resource instances can grant management of one canonical service to multiple hosts without transferring service ownership.

## Example Usage

```terraform
resource "freeipa_service" "router" {
  principal       = "HTTP/router.central.example.test"
  force           = true
  skip_host_check = true
}

resource "freeipa_service_managed_by_host" "etna" {
  principal = freeipa_service.router.principal
  host      = "etna.host.example.test"
}

resource "freeipa_service_managed_by_host" "rigi" {
  principal = freeipa_service.router.principal
  host      = "rigi.host.example.test"
}
```

## Import Usage

```terraform
import {
  to = freeipa_service_managed_by_host.rigi
  id = "HTTP/router.central.example.test|rigi.host.example.test"
}
```

## Schema

### Required

- `principal` (String) Canonical FreeIPA service principal.
- `host` (String) FreeIPA host FQDN to add to the service `managedBy` relationship.

### Read-Only

- `id` (String) ID of the association.
