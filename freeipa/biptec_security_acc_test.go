// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	version "github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func biptecTestAccRequireKerberos(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC is not set")
	}
	for _, key := range []string{
		"FREEIPA_HOST",
		"FREEIPA_KERBEROS_PRINCIPAL",
		"FREEIPA_KRB5_CONF",
		"FREEIPA_KEYTAB",
		"FREEIPA_TEST_ZONE",
	} {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			t.Skipf("%s is not set; skipping BIPTEC Kerberos acceptance tests", key)
		}
	}
}

func biptecTestAccKerberosProvider(principal, krb5Conf, keytab string) string {
	realm := strings.TrimSpace(os.Getenv("FREEIPA_KERBEROS_REALM"))
	realmConfig := ""
	if realm != "" {
		realmConfig = fmt.Sprintf("  kerberos_realm = %q\n", realm)
	}
	return fmt.Sprintf(`
provider "freeipa" {
  host               = %q
  kerberos_principal = %q
%s  krb5_conf_path     = %q
  keytab_path        = %q
  insecure           = true
}
`, os.Getenv("FREEIPA_HOST"), principal, realmConfig, krb5Conf, keytab)
}

func biptecTestAccDefaultKerberosProvider() string {
	return biptecTestAccKerberosProvider(
		os.Getenv("FREEIPA_KERBEROS_PRINCIPAL"),
		os.Getenv("FREEIPA_KRB5_CONF"),
		os.Getenv("FREEIPA_KEYTAB"),
	)
}

func biptecTestAccZone() string {
	return strings.TrimSpace(os.Getenv("FREEIPA_TEST_ZONE"))
}

func biptecTestAccHostName(prefix string) string {
	return prefix + "." + strings.TrimSuffix(biptecTestAccZone(), ".")
}

func biptecTestSecret(t *testing.T, prefix string) string {
	t.Helper()
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate acceptance secret: %v", err)
	}
	return prefix + hex.EncodeToString(buf)
}

func biptecTestAccWriteOnlyHostConfig(version int64) string {
	return biptecTestAccDefaultKerberosProvider() + fmt.Sprintf(`
variable "freeipa_enrollment_password" {
  type      = string
  sensitive = true
  ephemeral = true
  default   = null
}

resource "freeipa_host" "writeonly" {
  name                    = %q
  ip_address              = "10.254.250.78"
  force                   = true
  userpassword_wo         = var.freeipa_enrollment_password
  userpassword_wo_version = %d
}
`, biptecTestAccHostName("testacc-biptec-writeonly"), version)
}

func TestAccBIPTECKerberosAuthentication(t *testing.T) {
	biptecTestAccRequireKerberos(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: biptecTestAccDefaultKerberosProvider() + fmt.Sprintf(`
data "freeipa_dns_zone" "kerberos" {
  zone_name = %q
}
`, biptecTestAccZone()),
			Check: resource.TestCheckResourceAttr("data.freeipa_dns_zone.kerberos", "zone_name", biptecTestAccZone()),
		}},
	})
}

func TestAccBIPTECKerberosDNSRecord(t *testing.T) {
	biptecTestAccRequireKerberos(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: biptecTestAccDefaultKerberosProvider() + fmt.Sprintf(`
resource "freeipa_dns_record" "kerberos" {
  zone_name = %q
  name      = "testacc-biptec-kerberos"
  type      = "A"
  records   = ["192.0.2.77"]
}
`, biptecTestAccZone()),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("freeipa_dns_record.kerberos", "type", "A"),
				resource.TestCheckResourceAttr("freeipa_dns_record.kerberos", "records.0", "192.0.2.77"),
			),
		}},
	})
}

func TestAccBIPTECKerberosNoPasswordFallback(t *testing.T) {
	biptecTestAccRequireKerberos(t)
	if os.Getenv("FREEIPA_USERNAME") == "" || os.Getenv("FREEIPA_PASSWORD") == "" {
		t.Fatal("FREEIPA_USERNAME and FREEIPA_PASSWORD must be set to prove Kerberos precedence")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: biptecTestAccKerberosProvider(
				os.Getenv("FREEIPA_KERBEROS_PRINCIPAL"),
				os.Getenv("FREEIPA_KRB5_CONF"),
				"/tmp/biptec-keytab-must-not-exist",
			) + fmt.Sprintf(`
data "freeipa_dns_zone" "no_fallback" {
  zone_name = %q
}
`, biptecTestAccZone()),
			ExpectError: regexp.MustCompile(`(?i)open Kerberos keytab`),
		}},
	})
}

func TestAccBIPTECKerberosInvalidPrincipal(t *testing.T) {
	biptecTestAccRequireKerberos(t)
	realm := strings.TrimSpace(os.Getenv("FREEIPA_KERBEROS_REALM"))
	if realm == "" {
		parts := strings.SplitN(os.Getenv("FREEIPA_KERBEROS_PRINCIPAL"), "@", 2)
		if len(parts) != 2 {
			t.Fatal("FREEIPA_KERBEROS_REALM is required when principal has no realm")
		}
		realm = parts[1]
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: biptecTestAccKerberosProvider(
				"biptec-principal-does-not-exist@"+realm,
				os.Getenv("FREEIPA_KRB5_CONF"),
				os.Getenv("FREEIPA_KEYTAB"),
			) + fmt.Sprintf(`
data "freeipa_dns_zone" "bad_principal" {
  zone_name = %q
}
`, biptecTestAccZone()),
			ExpectError: regexp.MustCompile(`(?is)(initial login failed|Kerberos authentication did not return a FreeIPA API\s+client)`),
		}},
	})
}

func TestAccBIPTECKerberosMalformedConfig(t *testing.T) {
	biptecTestAccRequireKerberos(t)
	badConfig := t.TempDir() + "/krb5.conf"
	if err := os.WriteFile(badConfig, []byte("this is not a kerberos configuration\n"), 0o600); err != nil {
		t.Fatalf("write malformed krb5.conf: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: biptecTestAccKerberosProvider(
				os.Getenv("FREEIPA_KERBEROS_PRINCIPAL"),
				badConfig,
				os.Getenv("FREEIPA_KEYTAB"),
			) + fmt.Sprintf(`
data "freeipa_dns_zone" "bad_krb5" {
  zone_name = %q
}
`, biptecTestAccZone()),
			ExpectError: regexp.MustCompile(`(?is)(reading kerberos configuration|Kerberos authentication did not return a FreeIPA API\s+client)`),
		}},
	})
}

func TestAccBIPTECHostWriteOnlyEnrollmentPassword(t *testing.T) {
	biptecTestAccRequireKerberos(t)
	secretV1 := biptecTestSecret(t, "BIPTEC_ACC_OTP1_")
	secretV2 := biptecTestSecret(t, "BIPTEC_ACC_OTP2_")
	t.Cleanup(func() { _ = os.Unsetenv("TF_VAR_freeipa_enrollment_password") })

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.11.0"))),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { _ = os.Setenv("TF_VAR_freeipa_enrollment_password", secretV1) },
				Config:    biptecTestAccWriteOnlyHostConfig(1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("freeipa_host.writeonly", "userpassword_wo_version", "1"),
					resource.TestCheckNoResourceAttr("freeipa_host.writeonly", "userpassword_wo"),
				),
			},
			{
				PreConfig: func() { _ = os.Setenv("TF_VAR_freeipa_enrollment_password", secretV2) },
				Config:    biptecTestAccWriteOnlyHostConfig(2),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("freeipa_host.writeonly", plancheck.ResourceActionUpdate),
				}},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("freeipa_host.writeonly", "userpassword_wo_version", "2"),
					resource.TestCheckNoResourceAttr("freeipa_host.writeonly", "userpassword_wo"),
				),
			},
			{
				PreConfig:   func() { _ = os.Unsetenv("TF_VAR_freeipa_enrollment_password") },
				Config:      biptecTestAccWriteOnlyHostConfig(3),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Invalid Enrollment Password Rotation`),
			},
			{
				PreConfig: func() { _ = os.Unsetenv("TF_VAR_freeipa_enrollment_password") },
				Config:    biptecTestAccWriteOnlyHostConfig(2),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("freeipa_host.writeonly", plancheck.ResourceActionNoop),
				}},
			},
		},
	})
}
