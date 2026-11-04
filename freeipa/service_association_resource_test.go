// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	ipa "github.com/infra-monkey/go-freeipa/freeipa"
)

func TestServiceAssociationSchemas(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		resource   resource.Resource
		typeName   string
		attributes []string
	}{
		{
			name:       "principal alias",
			resource:   &ServicePrincipalAliasResource{},
			typeName:   "freeipa_service_principal_alias",
			attributes: []string{"id", "principal", "alias"},
		},
		{
			name:       "managed by host",
			resource:   &ServiceManagedByHostResource{},
			typeName:   "freeipa_service_managed_by_host",
			attributes: []string{"id", "principal", "host"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var metadata resource.MetadataResponse
			tc.resource.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "freeipa"}, &metadata)
			if metadata.TypeName != tc.typeName {
				t.Fatalf("unexpected resource type: %q", metadata.TypeName)
			}
			var schemaResp resource.SchemaResponse
			tc.resource.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("schema diagnostics: %v", schemaResp.Diagnostics)
			}
			for _, name := range tc.attributes {
				if _, ok := schemaResp.Schema.Attributes[name]; !ok {
					t.Fatalf("missing schema attribute %q", name)
				}
			}
		})
	}
}

func TestNormalizeServicePrincipal(t *testing.T) {
	if normalizeServicePrincipal(" HTTP/router.central.example.test@EXAMPLE.TEST ") != "HTTP/router.central.example.test" {
		t.Fatal("principal normalization failed")
	}
	if normalizeServicePrincipal("HTTP/router.central.example.test") != "HTTP/router.central.example.test" {
		t.Fatal("principal without realm changed unexpectedly")
	}
}

func TestServiceHostMembershipMutationError(t *testing.T) {
	if err := serviceHostMembershipMutationError(1, ipa.FailedOperations{}); err != nil {
		t.Fatalf("one completed host membership mutation must be accepted: %v", err)
	}

	var failed ipa.FailedOperations
	if err := json.Unmarshal([]byte(`{"managedby":{"host":[["baker.host.biptec.net","Insufficient access"]]}}`), &failed); err != nil {
		t.Fatalf("decode failed membership fixture: %v", err)
	}

	err := serviceHostMembershipMutationError(0, failed)
	if err == nil {
		t.Fatal("zero completed host membership mutations must not be reported as success")
	}
	for _, want := range []string{"completed 0", "managedby/host/baker.host.biptec.net", "Insufficient access"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("membership failure %q does not contain %q", err, want)
		}
	}
}

func TestParseServiceAssociationImportID(t *testing.T) {
	principal, association, err := parseServiceAssociationImportID("HTTP/router.example.test|etna.host.example.test")
	if err != nil {
		t.Fatalf("unexpected import parse error: %v", err)
	}
	if principal != "HTTP/router.example.test" || association != "etna.host.example.test" {
		t.Fatalf("unexpected parsed values: %q %q", principal, association)
	}
	for _, value := range []string{"", "missing-separator", "|host", "principal|"} {
		if _, _, err := parseServiceAssociationImportID(value); err == nil {
			t.Fatalf("expected import parse failure for %q", value)
		}
	}
}
