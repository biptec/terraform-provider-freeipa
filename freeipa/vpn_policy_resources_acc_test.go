// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

const (
	vpnPolicyAccHost            = "issue68-policy.ipatest.lan"
	vpnPolicyAccService         = "ISSUE68/issue68-policy.ipatest.lan"
	vpnPolicyAccProfile         = "Issue68ProviderProfileAcc"
	vpnPolicyAccCAACL           = "issue68-provider-ca-acl-acc"
	vpnPolicyAccHBAC            = "issue68-provider-hbac-acc"
	vpnPolicyAccPermission      = "issue68-provider-permission-acc"
	vpnPolicyAccAdminPermission = "issue68-provider-admin-permission-acc"
	vpnPolicyAccPrivilege       = "issue68-provider-privilege-acc"
	vpnPolicyAccRole            = "issue68-provider-role-acc"
)

func testAccVPNPolicyResourcesConfig(t *testing.T, updated bool) string {
	t.Helper()
	profileBytes, err := os.ReadFile("testdata/issue68_certprofile.cfg")
	if err != nil {
		t.Fatalf("read certificate profile fixture: %v", err)
	}
	profile := string(profileBytes)
	descriptionSuffix := ""
	storeIssued := "false"
	if updated {
		descriptionSuffix = " updated"
		storeIssued = "true"
		if !strings.Contains(profile, "visible=false") {
			t.Fatal("certificate profile fixture does not contain visible=false")
		}
		profile = strings.Replace(profile, "visible=false", "visible=true", 1)
	}

	targetDN := "fqdn=" + vpnPolicyAccHost + ",cn=computers,cn=accounts,dc=ipatest,dc=lan"

	return testAccFreeIPAProvider() +
		"resource \"freeipa_host\" \"issue68\" {\n" +
		"  name        = \"" + vpnPolicyAccHost + "\"\n" +
		"  description = \"Issue 68 policy acceptance host\"\n" +
		"  force       = true\n" +
		"}\n\n" +
		"resource \"freeipa_service\" \"issue68\" {\n" +
		"  principal       = \"" + vpnPolicyAccService + "\"\n" +
		"  adopt_existing  = false\n" +
		"  force           = true\n" +
		"  skip_host_check = false\n" +
		"  depends_on      = [freeipa_host.issue68]\n" +
		"}\n\n" +
		"data \"freeipa_service\" \"issue68\" {\n" +
		"  principal  = freeipa_service.issue68.principal\n" +
		"  depends_on = [freeipa_service.issue68]\n" +
		"}\n\n" +
		"resource \"freeipa_hbac_service\" \"issue68\" {\n" +
		"  name        = \"" + vpnPolicyAccHBAC + "\"\n" +
		"  description = \"Issue 68 HBAC service" + descriptionSuffix + "\"\n" +
		"}\n\n" +
		"resource \"freeipa_certprofile\" \"issue68\" {\n" +
		"  name         = \"" + vpnPolicyAccProfile + "\"\n" +
		"  description  = \"Issue 68 certificate profile" + descriptionSuffix + "\"\n" +
		"  store_issued = " + storeIssued + "\n" +
		"  config       = " + strconv.Quote(profile) + "\n" +
		"}\n\n" +
		"data \"freeipa_certprofile\" \"issue68\" {\n" +
		"  name       = freeipa_certprofile.issue68.name\n" +
		"  depends_on = [freeipa_certprofile.issue68]\n" +
		"}\n\n" +
		"resource \"freeipa_ca_acl\" \"issue68\" {\n" +
		"  name        = \"" + vpnPolicyAccCAACL + "\"\n" +
		"  description = \"Issue 68 CA ACL" + descriptionSuffix + "\"\n" +
		"  enabled     = true\n" +
		"}\n\n" +
		"resource \"freeipa_ca_acl_profile_membership\" \"issue68\" {\n" +
		"  ca_acl  = freeipa_ca_acl.issue68.name\n" +
		"  profile = freeipa_certprofile.issue68.name\n" +
		"}\n\n" +
		"resource \"freeipa_ca_acl_service_membership\" \"issue68\" {\n" +
		"  ca_acl     = freeipa_ca_acl.issue68.name\n" +
		"  service    = \"" + vpnPolicyAccService + "\"\n" +
		"  depends_on = [freeipa_service.issue68]\n" +
		"}\n\n" +
		"resource \"freeipa_permission\" \"issue68\" {\n" +
		"  name                = \"" + vpnPolicyAccPermission + "\"\n" +
		"  description         = \"Issue 68 permission" + descriptionSuffix + "\"\n" +
		"  rights              = [\"write\"]\n" +
		"  included_attributes = [\"krbprincipalname\"]\n" +
		"  target              = \"" + targetDN + "\"\n" +
		"  depends_on          = [freeipa_host.issue68]\n" +
		"}\n\n" +
		"resource \"freeipa_permission\" \"issue68_admin\" {\n" +
		"  name                = \"" + vpnPolicyAccAdminPermission + "\"\n" +
		"  description         = \"Issue 68 admin certificate permission" + descriptionSuffix + "\"\n" +
		"  rights              = [\"write\"]\n" +
		"  included_attributes = [\"usercertificate\"]\n" +
		"  object_type         = \"user\"\n" +
		"  member_of           = [\"admins\"]\n" +
		"}\n\n" +
		"resource \"freeipa_privilege\" \"issue68\" {\n" +
		"  name        = \"" + vpnPolicyAccPrivilege + "\"\n" +
		"  description = \"Issue 68 privilege" + descriptionSuffix + "\"\n" +
		"}\n\n" +
		"resource \"freeipa_privilege_permission_membership\" \"issue68\" {\n" +
		"  privilege  = freeipa_privilege.issue68.name\n" +
		"  permission = freeipa_permission.issue68.name\n" +
		"}\n\n" +
		"resource \"freeipa_role\" \"issue68\" {\n" +
		"  name        = \"" + vpnPolicyAccRole + "\"\n" +
		"  description = \"Issue 68 role" + descriptionSuffix + "\"\n" +
		"}\n\n" +
		"resource \"freeipa_role_privilege_membership\" \"issue68\" {\n" +
		"  role      = freeipa_role.issue68.name\n" +
		"  privilege = freeipa_privilege.issue68.name\n" +
		"}\n\n" +
		"resource \"freeipa_role_host_membership\" \"issue68\" {\n" +
		"  role = freeipa_role.issue68.name\n" +
		"  host = \"" + vpnPolicyAccHost + "\"\n" +
		"  depends_on = [freeipa_host.issue68]\n" +
		"}\n\n" +
		"resource \"freeipa_role_service_membership\" \"issue68\" {\n" +
		"  role    = freeipa_role.issue68.name\n" +
		"  service = \"" + vpnPolicyAccService + "\"\n" +
		"  depends_on = [freeipa_service.issue68]\n" +
		"}\n\n" +
		"resource \"freeipa_service_keytab_host\" \"issue68\" {\n" +
		"  principal = \"" + vpnPolicyAccService + "\"\n" +
		"  host      = \"" + vpnPolicyAccHost + "\"\n" +
		"  depends_on = [freeipa_service.issue68, freeipa_host.issue68]\n" +
		"}\n"
}

func TestAccVPNPolicyResources(t *testing.T) {
	baseConfig := testAccVPNPolicyResourcesConfig(t, false)
	updatedConfig := testAccVPNPolicyResourcesConfig(t, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("freeipa_hbac_service.issue68", "description", "Issue 68 HBAC service"),
					resource.TestCheckResourceAttr("freeipa_certprofile.issue68", "store_issued", "false"),
					resource.TestCheckResourceAttr("freeipa_certprofile.issue68", "description", "Issue 68 certificate profile"),
					resource.TestCheckResourceAttr("freeipa_ca_acl.issue68", "enabled", "true"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68", "description", "Issue 68 permission"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68", "rights.#", "1"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68", "included_attributes.#", "1"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68_admin", "description", "Issue 68 admin certificate permission"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68_admin", "object_type", "user"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68_admin", "member_of.#", "1"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68_admin", "member_of.0", "admins"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68_admin", "included_attributes.#", "1"),
					resource.TestCheckResourceAttr("freeipa_privilege.issue68", "description", "Issue 68 privilege"),
					resource.TestCheckResourceAttr("freeipa_role.issue68", "description", "Issue 68 role"),
					resource.TestCheckResourceAttr("freeipa_ca_acl_service_membership.issue68", "service", vpnPolicyAccService),
					resource.TestCheckResourceAttr("freeipa_role_service_membership.issue68", "service", vpnPolicyAccService),
					resource.TestCheckResourceAttr("freeipa_service_keytab_host.issue68", "principal", vpnPolicyAccService),
					resource.TestCheckResourceAttr("freeipa_service_keytab_host.issue68", "host", vpnPolicyAccHost),
					resource.TestCheckResourceAttrSet("data.freeipa_service.issue68", "dn"),
					resource.TestCheckResourceAttr("data.freeipa_certprofile.issue68", "description", "Issue 68 certificate profile"),
					resource.TestCheckResourceAttr("data.freeipa_certprofile.issue68", "store_issued", "false"),
				),
			},
			{
				Config: baseConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:      "freeipa_hbac_service.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccHBAC,
				ImportStateVerify: true,
			},
			{
				ResourceName:            "freeipa_certprofile.issue68",
				ImportState:             true,
				ImportStateId:           vpnPolicyAccProfile,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"config"},
			},
			{
				ResourceName:      "freeipa_ca_acl.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccCAACL,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_ca_acl_profile_membership.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccCAACL + "/" + vpnPolicyAccProfile,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_ca_acl_service_membership.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccCAACL + "/ISSUE68%2Fissue68-policy.ipatest.lan",
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_permission.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccPermission,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_permission.issue68_admin",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccAdminPermission,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_privilege.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccPrivilege,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_privilege_permission_membership.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccPrivilege + "/" + vpnPolicyAccPermission,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_role.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccRole,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_role_privilege_membership.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccRole + "/" + vpnPolicyAccPrivilege,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_role_host_membership.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccRole + "/" + vpnPolicyAccHost,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_role_service_membership.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccRole + "/ISSUE68%2Fissue68-policy.ipatest.lan",
				ImportStateVerify: true,
			},
			{
				ResourceName:      "freeipa_service_keytab_host.issue68",
				ImportState:       true,
				ImportStateId:     vpnPolicyAccService + "|" + vpnPolicyAccHost,
				ImportStateVerify: true,
			},
			{
				Config: baseConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("freeipa_hbac_service.issue68", "description", "Issue 68 HBAC service updated"),
					resource.TestCheckResourceAttr("freeipa_certprofile.issue68", "description", "Issue 68 certificate profile updated"),
					resource.TestCheckResourceAttr("freeipa_certprofile.issue68", "store_issued", "true"),
					resource.TestCheckResourceAttr("freeipa_ca_acl.issue68", "description", "Issue 68 CA ACL updated"),
					resource.TestCheckResourceAttr("freeipa_permission.issue68", "description", "Issue 68 permission updated"),
					resource.TestCheckResourceAttr("freeipa_privilege.issue68", "description", "Issue 68 privilege updated"),
					resource.TestCheckResourceAttr("freeipa_role.issue68", "description", "Issue 68 role updated"),
				),
			},
			{
				Config: updatedConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

func TestVPNPolicyAcceptanceConfigTargetsExpectedRealm(t *testing.T) {
	config := testAccVPNPolicyResourcesConfig(t, false)
	for _, needle := range []string{
		fmt.Sprintf("name        = %q", vpnPolicyAccHost),
		fmt.Sprintf("principal       = %q", vpnPolicyAccService),
		"dc=ipatest,dc=lan",
		"profileId=Issue68ProviderProfileAcc",
	} {
		if !strings.Contains(config, needle) {
			t.Fatalf("generated acceptance config missing %q", needle)
		}
	}
}
