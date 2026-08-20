terraform {
  required_providers {
    freeipa = {
      version = "5.5.0"
      source  = "rework-space-com/freeipa"
    }
  }
}

# Existing username/password mode.
provider "freeipa" {
  host     = "ipa.example.test"
  username = "admin"
  password = var.freeipa_password
  insecure = true
}

# For automation, Kerberos/keytab can be used instead. If any Kerberos
# setting is present, Kerberos takes precedence and there is no password
# fallback on authentication errors.
#
# provider "freeipa" {
#   host               = "ipa.example.test"
#   kerberos_principal = "terraform/runner@EXAMPLE.TEST"
#   krb5_conf_path     = "/etc/krb5.conf"
#   keytab_path        = "/run/secrets/freeipa.keytab"
# }
