resource "freeipa_host" "host-1" {
  name          = "host-1.example.test"
  ip_address    = "192.168.1.65"
  description   = "FreeIPA client in example.test domain"
  mac_addresses = ["00:00:00:AA:AA:AA", "00:00:00:BB:BB:BB"]
}

# Terraform/OpenTofu 1.11+ only. The enrollment password is caller-supplied,
# sensitive, ephemeral, and never persisted in state by the provider.
variable "freeipa_enrollment_password" {
  type      = string
  sensitive = true
  ephemeral = true
  default   = null
}

resource "freeipa_host" "bulk-enrollment" {
  name                    = "host-2.example.test"
  ip_address              = "192.168.1.66"
  force                   = true
  userpassword_wo         = var.freeipa_enrollment_password
  userpassword_wo_version = 1
}
