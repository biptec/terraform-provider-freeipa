// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	ipa "github.com/infra-monkey/go-freeipa/freeipa"
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
	for _, name := range []string{"id", "principal", "adopt_existing", "force", "skip_host_check"} {
		if _, ok := schemaResp.Schema.Attributes[name]; !ok {
			t.Fatalf("missing schema attribute %q", name)
		}
	}
	for _, name := range []string{"force", "skip_host_check"} {
		attr, ok := schemaResp.Schema.Attributes[name].(schema.BoolAttribute)
		if !ok {
			t.Fatalf("%s is not a bool attribute", name)
		}
		if len(attr.PlanModifiers) != 0 {
			t.Fatalf("%s must not require replacement; it is create-time metadata", name)
		}
	}
}

func TestServiceAddResponseDecodeError(t *testing.T) {
	if !serviceAddResponseDecodeError(errors.New("unexpected value for field Subject: <nil> (<nil>)")) {
		t.Fatal("expected generated response-decoder error to be recoverable")
	}
	if serviceAddResponseDecodeError(&ipa.Error{Name: "DNSNotARecordError", Code: 4019, Message: "missing DNS record"}) {
		t.Fatal("FreeIPA API errors must never be treated as response-decoder errors")
	}
	if serviceAddResponseDecodeError(errors.New("connection refused")) {
		t.Fatal("unrelated transport errors must not be treated as response-decoder errors")
	}
	if serviceAddResponseDecodeError(nil) {
		t.Fatal("nil error must not be recoverable")
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
