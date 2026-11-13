// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	ipa "github.com/infra-monkey/go-freeipa/freeipa"
)

func TestVPNPolicyResourcesRegistered(t *testing.T) {
	ctx := context.Background()
	provider := &freeipaProvider{}
	want := map[string]bool{
		"freeipa_hbac_service":                    false,
		"freeipa_certprofile":                     false,
		"freeipa_ca_acl":                          false,
		"freeipa_ca_acl_profile_membership":       false,
		"freeipa_ca_acl_service_membership":       false,
		"freeipa_permission":                      false,
		"freeipa_privilege":                       false,
		"freeipa_privilege_permission_membership": false,
		"freeipa_role":                            false,
		"freeipa_role_privilege_membership":       false,
		"freeipa_role_host_membership":            false,
		"freeipa_role_service_membership":         false,
		"freeipa_service_keytab_host":             false,
	}
	for _, constructor := range provider.Resources(ctx) {
		instance := constructor()
		var metadata resource.MetadataResponse
		instance.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "freeipa"}, &metadata)
		if _, ok := want[metadata.TypeName]; ok {
			want[metadata.TypeName] = true
		}
	}
	for typeName, found := range want {
		if !found {
			t.Errorf("provider does not register %s", typeName)
		}
	}
}

func TestVPNPolicyDataSourcesRegisteredAndSchema(t *testing.T) {
	ctx := context.Background()
	provider := &freeipaProvider{}
	want := map[string][]string{
		"freeipa_certprofile": {"id", "name", "description", "store_issued", "config"},
		"freeipa_service":     {"id", "principal", "dn"},
	}
	found := map[string]bool{}
	for _, constructor := range provider.DataSources(ctx) {
		instance := constructor()
		var metadata datasource.MetadataResponse
		instance.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "freeipa"}, &metadata)
		attributes, ok := want[metadata.TypeName]
		if !ok {
			continue
		}
		found[metadata.TypeName] = true
		var schemaResp datasource.SchemaResponse
		instance.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)
		if schemaResp.Diagnostics.HasError() {
			t.Fatalf("%s schema diagnostics: %v", metadata.TypeName, schemaResp.Diagnostics)
		}
		for _, attr := range attributes {
			if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
				t.Errorf("%s missing attribute %q", metadata.TypeName, attr)
			}
		}
	}
	for typeName := range want {
		if !found[typeName] {
			t.Errorf("provider does not register data source %s", typeName)
		}
	}
}

func TestVPNPolicyResourceSchemas(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name        string
		constructor func() resource.Resource
		typeName    string
		attributes  []string
	}{
		{"hbac service", NewHbacServiceResource, "freeipa_hbac_service", []string{"id", "name", "description"}},
		{"certificate profile", NewCertprofileResource, "freeipa_certprofile", []string{"id", "name", "description", "store_issued", "config"}},
		{"CA ACL", NewCAACLResource, "freeipa_ca_acl", []string{"id", "name", "description", "enabled", "ca_category", "profile_category", "user_category", "host_category", "service_category"}},
		{"CA ACL profile membership", NewCAACLProfileMembershipResource, "freeipa_ca_acl_profile_membership", []string{"id", "ca_acl", "profile"}},
		{"CA ACL service membership", NewCAACLServiceMembershipResource, "freeipa_ca_acl_service_membership", []string{"id", "ca_acl", "service"}},
		{"permission", NewPermissionResource, "freeipa_permission", []string{"id", "name", "description", "rights", "included_attributes", "target"}},
		{"privilege", NewPrivilegeResource, "freeipa_privilege", []string{"id", "name", "description"}},
		{"privilege permission membership", NewPrivilegePermissionMembershipResource, "freeipa_privilege_permission_membership", []string{"id", "privilege", "permission"}},
		{"role", NewRoleResource, "freeipa_role", []string{"id", "name", "description"}},
		{"role privilege membership", NewRolePrivilegeMembershipResource, "freeipa_role_privilege_membership", []string{"id", "role", "privilege"}},
		{"role host membership", NewRoleHostMembershipResource, "freeipa_role_host_membership", []string{"id", "role", "host"}},
		{"role service membership", NewRoleServiceMembershipResource, "freeipa_role_service_membership", []string{"id", "role", "service"}},
		{"service keytab host", NewServiceKeytabHostResource, "freeipa_service_keytab_host", []string{"id", "principal", "host"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := tt.constructor()
			var metadata resource.MetadataResponse
			instance.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "freeipa"}, &metadata)
			if metadata.TypeName != tt.typeName {
				t.Fatalf("unexpected type name: got %q want %q", metadata.TypeName, tt.typeName)
			}
			var schemaResp resource.SchemaResponse
			instance.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("schema diagnostics: %v", schemaResp.Diagnostics)
			}
			for _, attr := range tt.attributes {
				if _, ok := schemaResp.Schema.Attributes[attr]; !ok {
					t.Errorf("missing attribute %q", attr)
				}
			}
		})
	}
}

func TestPolicyMembershipIDRoundTrip(t *testing.T) {
	parent := "vpn-server-certificates"
	member := "VPN/pizol.host.sandbox.biptec.net@CENTRAL.SANDBOX.BIPTEC.NET"
	id := policyMembershipID(parent, member)
	if !strings.Contains(id, "VPN%2Fpizol") {
		t.Fatalf("service slash was not escaped in %q", id)
	}
	gotParent, gotMember, err := parsePolicyMembershipID(id)
	if err != nil {
		t.Fatalf("parse membership ID: %v", err)
	}
	if gotParent != parent || gotMember != member {
		t.Fatalf("round trip mismatch: got (%q, %q), want (%q, %q)", gotParent, gotMember, parent, member)
	}
}

func TestParsePolicyMembershipIDRejectsInvalidID(t *testing.T) {
	for _, id := range []string{"", "only-parent", "/member", "parent/"} {
		if _, _, err := parsePolicyMembershipID(id); err == nil {
			t.Errorf("expected %q to be rejected", id)
		}
	}
}

func TestCreatePolicyMembershipRejectsFreeIPAFalseSuccess(t *testing.T) {
	var failed ipa.FailedOperations
	if err := json.Unmarshal(
		[]byte(`{"member":{"privilege":[["VPN Certificate Management","Insufficient access"]]}}`),
		&failed,
	); err != nil {
		t.Fatalf("decode failed operations: %v", err)
	}

	verifyCalled := false
	err := createPolicyMembership(
		"role",
		"VPN Certificate Manager",
		"privilege",
		"VPN Certificate Management",
		func() (int, ipa.FailedOperations, error) {
			return 0, failed, nil
		},
		func() (bool, error) {
			verifyCalled = true
			return false, nil
		},
	)
	if err == nil {
		t.Fatal("completed=0 membership mutation must not be reported as success")
	}
	if verifyCalled {
		t.Fatal("read-back must not run after FreeIPA reports a failed/no-op create mutation")
	}
	for _, want := range []string{"completed 0", "VPN Certificate Management", "Insufficient access"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("false-success error %q does not contain %q", err, want)
		}
	}
}

func TestCreatePolicyMembershipRequiresReadBackPostcondition(t *testing.T) {
	err := createPolicyMembership(
		"role",
		"VPN Certificate Manager",
		"privilege",
		"VPN Certificate Management",
		func() (int, ipa.FailedOperations, error) {
			return 1, nil, nil
		},
		func() (bool, error) {
			return false, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "membership is absent on read-back") {
		t.Fatalf("missing read-back postcondition must fail, got %v", err)
	}
}

func TestCreatePolicyMembershipAcceptsVerifiedMutation(t *testing.T) {
	err := createPolicyMembership(
		"role",
		"VPN Certificate Manager",
		"service",
		"VPN/pizol.host.biptec.net",
		func() (int, ipa.FailedOperations, error) {
			return 1, nil, nil
		},
		func() (bool, error) {
			return true, nil
		},
	)
	if err != nil {
		t.Fatalf("verified membership mutation must succeed: %v", err)
	}
}

func TestDeletePolicyMembershipRequiresAbsenceOnReadBack(t *testing.T) {
	err := deletePolicyMembership(
		"role",
		"VPN Certificate Manager",
		"host",
		"pizol.host.biptec.net",
		func() error { return nil },
		func() (bool, error) { return true, nil },
	)
	if err == nil || !strings.Contains(err.Error(), "still a member") {
		t.Fatalf("delete must fail while membership remains, got %v", err)
	}
}

func TestServicePrincipalEquivalent(t *testing.T) {
	tests := []struct {
		actual string
		want   string
		equal  bool
	}{
		{"VPN/pizol.host.sandbox.biptec.net@CENTRAL.SANDBOX.BIPTEC.NET", "VPN/pizol.host.sandbox.biptec.net", true},
		{"vpn/PIZOL.HOST.SANDBOX.BIPTEC.NET@central.sandbox.biptec.net", "VPN/pizol.host.sandbox.biptec.net", true},
		{"VPN/pizol.host.sandbox.biptec.net", "VPN/pizol.host.sandbox.biptec.net@CENTRAL.SANDBOX.BIPTEC.NET", true},
		{"VPNCLIENT/pizol.host.sandbox.biptec.net@CENTRAL.SANDBOX.BIPTEC.NET", "VPN/pizol.host.sandbox.biptec.net", false},
	}
	for _, tt := range tests {
		if got := servicePrincipalEquivalent(tt.actual, tt.want); got != tt.equal {
			t.Errorf("servicePrincipalEquivalent(%q, %q) = %v, want %v", tt.actual, tt.want, got, tt.equal)
		}
	}
}

func TestCertprofileConfigSemanticEquality(t *testing.T) {
	ctx := context.Background()
	withoutNewline := certprofileConfigValueFromString("profileId=Issue68\nvisible=false")
	withNewline := certprofileConfigValueFromString("profileId=Issue68\nvisible=false\n")
	equal, diags := withoutNewline.StringSemanticEquals(ctx, withNewline)
	if diags.HasError() {
		t.Fatalf("semantic equality diagnostics: %v", diags)
	}
	if !equal {
		t.Fatal("certificate profile configs differing only by trailing newline must be semantically equal")
	}
	different := certprofileConfigValueFromString("profileId=Issue68\nvisible=true\n")
	equal, diags = withoutNewline.StringSemanticEquals(ctx, different)
	if diags.HasError() {
		t.Fatalf("semantic equality diagnostics: %v", diags)
	}
	if equal {
		t.Fatal("certificate profile content drift must not be semantically equal")
	}
}

func TestRawFreeIPAClientRegistrationIsLazy(t *testing.T) {
	client := &ipa.Client{}
	config := &freeipaProviderModel{}
	registerRawFreeIPAClientConfig(client, config)
	t.Cleanup(func() { rawFreeIPAClients.Delete(client) })

	value, ok := rawFreeIPAClients.Load(client)
	if !ok {
		t.Fatal("raw compatibility client registration is missing")
	}
	registration, ok := value.(*rawFreeIPAClientRegistration)
	if !ok {
		t.Fatalf("unexpected registration type %T", value)
	}
	if registration.client != nil || registration.err != nil {
		t.Fatal("raw compatibility client must not initialize during provider Configure")
	}
}

func TestRawFreeIPAValueDecoders(t *testing.T) {
	if got := rawString([]any{"value"}); got != "value" {
		t.Fatalf("rawString = %q", got)
	}
	if got := rawStrings([]any{"write", "read"}); len(got) != 2 || got[0] != "write" || got[1] != "read" {
		t.Fatalf("rawStrings = %#v", got)
	}
	for _, tc := range []struct {
		value any
		want  bool
	}{
		{true, true},
		{"TRUE", true},
		{[]any{"true"}, true},
		{"false", false},
	} {
		if got := rawBool(tc.value); got != tc.want {
			t.Errorf("rawBool(%#v) = %v, want %v", tc.value, got, tc.want)
		}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("profileId=Issue68\nvisible=false\n"))
	got, err := rawBinaryString(map[string]any{"__base64__": encoded})
	if err != nil {
		t.Fatalf("rawBinaryString: %v", err)
	}
	if got != "profileId=Issue68\nvisible=false\n" {
		t.Fatalf("decoded profile = %q", got)
	}
	if _, err := rawBinaryString(map[string]any{"__base64__": "%%%"}); err == nil {
		t.Fatal("invalid base64 must fail")
	}
}

func TestRawCompatibilityClientLazyPasswordLogin(t *testing.T) {
	var loginCount, jsonCount int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ipa/session/login_password":
			loginCount++
			http.SetCookie(w, &http.Cookie{Name: "ipa_session", Value: "test", Path: "/"})
			w.WriteHeader(http.StatusOK)
		case "/ipa/session/json":
			jsonCount++
			if _, err := r.Cookie("ipa_session"); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": nil,
				"result": map[string]any{
					"result": map[string]any{
						"cn":                  []any{"lazy-login-permission"},
						"description":         []any{"owner"},
						"ipapermright":        []any{"write"},
						"ipapermincludedattr": []any{"krbprincipalname"},
						"ipapermtarget":       []any{"cn=test,dc=example,dc=test"},
						"aci":                 nil,
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &rawFreeIPAClient{
		host:     strings.TrimPrefix(server.URL, "https://"),
		hc:       server.Client(),
		user:     "test-user",
		password: "test-password",
	}
	client.hc.Jar, _ = cookiejar.New(nil)
	permission, err := client.permissionShow("lazy-login-permission")
	if err != nil {
		t.Fatalf("permissionShow after lazy login: %v", err)
	}
	if permission.Name != "lazy-login-permission" {
		t.Fatalf("unexpected permission after lazy login: %#v", permission)
	}
	if loginCount != 1 || jsonCount != 2 {
		t.Fatalf("unexpected lazy login request counts: login=%d json=%d", loginCount, jsonCount)
	}
}

func TestRawCompatibilityClientDecodesFreeIPA413Responses(t *testing.T) {
	var sawPermission, sawProfile, sawCAACL, sawService bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ipa/session/json" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		method, _ := payload["method"].(string)
		params, _ := payload["params"].([]any)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "permission_show":
			sawPermission = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": nil,
				"result": map[string]any{
					"result": map[string]any{
						"cn":                  []any{"issue68-permission"},
						"description":         []any{"owner"},
						"ipapermright":        []any{"write"},
						"ipapermincludedattr": []any{"krbprincipalname"},
						"ipapermtarget":       []any{"krbprincipalname=VPN/pizol,cn=services,cn=accounts,dc=example,dc=test"},
						"aci":                 nil,
					},
				},
			})
		case "certprofile_show":
			sawProfile = true
			if len(params) != 2 {
				t.Fatalf("unexpected params length: %d", len(params))
			}
			kwargs, _ := params[1].(map[string]any)
			if kwargs["out"] != "-" {
				t.Fatalf("certprofile_show must request out, got %#v", kwargs["out"])
			}
			config := base64.StdEncoding.EncodeToString([]byte("profileId=Issue68Profile\nvisible=false\n"))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": nil,
				"result": map[string]any{
					"result": map[string]any{
						"cn":                        []any{"Issue68Profile"},
						"description":               []any{"profile owner"},
						"ipacertprofilestoreissued": []any{"FALSE"},
						"config":                    map[string]any{"__base64__": config},
					},
				},
			})
		case "caacl_show":
			sawCAACL = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": nil,
				"result": map[string]any{
					"result": map[string]any{
						"cn":                               []any{"issue68-caacl"},
						"description":                      []any{"acl owner"},
						"ipaenabledflag":                   []any{"TRUE"},
						"ipamembercertprofile_certprofile": []any{"ProfileA", "ProfileB"},
						"memberservice_service":            []any{"VPN/one.example.test@EXAMPLE.TEST", "VPN/two.example.test@EXAMPLE.TEST"},
					},
				},
			})
		case "service_show":
			sawService = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": nil,
				"result": map[string]any{
					"result": map[string]any{
						"krbcanonicalname": []any{"VPN/pizol.example.test@EXAMPLE.TEST"},
						"dn":               []any{"krbprincipalname=VPN/pizol.example.test@EXAMPLE.TEST,cn=services,cn=accounts,dc=example,dc=test"},
					},
				},
			})
		default:
			t.Fatalf("unexpected method %q", method)
		}
	}))
	defer server.Close()

	client := &rawFreeIPAClient{
		host: strings.TrimPrefix(server.URL, "https://"),
		hc:   server.Client(),
	}

	permission, err := client.permissionShow("issue68-permission")
	if err != nil {
		t.Fatalf("permissionShow: %v", err)
	}
	if permission.Name != "issue68-permission" ||
		permission.Description != "owner" ||
		len(permission.Rights) != 1 || permission.Rights[0] != "write" ||
		len(permission.IncludedAttributes) != 1 || permission.IncludedAttributes[0] != "krbprincipalname" {
		t.Fatalf("unexpected permission: %#v", permission)
	}

	profile, err := client.certprofileShow("Issue68Profile")
	if err != nil {
		t.Fatalf("certprofileShow: %v", err)
	}
	if profile.Name != "Issue68Profile" || profile.Description != "profile owner" || profile.StoreIssued {
		t.Fatalf("unexpected certprofile metadata: %#v", profile)
	}
	if profile.Config != "profileId=Issue68Profile\nvisible=false\n" {
		t.Fatalf("unexpected certprofile config %q", profile.Config)
	}

	acl, err := client.caACLShow("issue68-caacl")
	if err != nil {
		t.Fatalf("caACLShow: %v", err)
	}
	if !acl.Enabled || len(acl.Profiles) != 2 || len(acl.Services) != 2 {
		t.Fatalf("unexpected CA ACL: %#v", acl)
	}
	if !stringSliceContainsFold(&acl.Profiles, "ProfileB") {
		t.Fatalf("CA ACL profiles missing ProfileB: %#v", acl.Profiles)
	}
	if !stringSliceContainsServicePrincipal(acl.Services, "VPN/two.example.test") {
		t.Fatalf("CA ACL services missing realm-normalized principal: %#v", acl.Services)
	}
	service, err := client.serviceShow("VPN/pizol.example.test")
	if err != nil {
		t.Fatalf("serviceShow: %v", err)
	}
	if service.DN != "krbprincipalname=VPN/pizol.example.test@EXAMPLE.TEST,cn=services,cn=accounts,dc=example,dc=test" {
		t.Fatalf("unexpected service DN %q", service.DN)
	}

	if !sawPermission || !sawProfile || !sawCAACL || !sawService {
		t.Fatalf("expected all compatibility methods, permission=%v profile=%v caacl=%v service=%v", sawPermission, sawProfile, sawCAACL, sawService)
	}
}
