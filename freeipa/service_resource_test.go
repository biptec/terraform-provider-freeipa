// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestServiceResourceMetadataAndSchema(t *testing.T) {
	ctx := context.Background()
	r := &ServiceResource{}

	var metadata resource.MetadataResponse
	r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "freeipa"}, &metadata)
	if metadata.TypeName != "freeipa_service" {
		t.Fatalf("unexpected resource type: %q", metadata.TypeName)
	}

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", schemaResp.Diagnostics)
	}
	for _, name := range []string{"id", "principal", "managed_by_host", "force", "skip_host_check"} {
		if _, ok := schemaResp.Schema.Attributes[name]; !ok {
			t.Fatalf("missing schema attribute %q", name)
		}
	}
}

func TestServiceNotFound(t *testing.T) {
	if !serviceNotFound(errors.New("NotFound (4001): service not found")) {
		t.Fatal("expected NotFound error to be recognized")
	}
	if serviceNotFound(errors.New("permission denied")) {
		t.Fatal("unexpected non-NotFound error match")
	}
	if serviceNotFound(nil) {
		t.Fatal("nil error must not be treated as NotFound")
	}
}
