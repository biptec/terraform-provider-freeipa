package freeipa

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestHostEnrollmentPasswordSchema(t *testing.T) {
	var resp resource.SchemaResponse
	(&HostResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	secret, ok := resp.Schema.Attributes["userpassword_wo"].(resourceschema.StringAttribute)
	if !ok {
		t.Fatalf("userpassword_wo has unexpected schema type %T", resp.Schema.Attributes["userpassword_wo"])
	}
	if !secret.Optional || !secret.Sensitive || !secret.WriteOnly || secret.Computed {
		t.Fatalf("unexpected userpassword_wo contract: optional=%v sensitive=%v writeOnly=%v computed=%v", secret.Optional, secret.Sensitive, secret.WriteOnly, secret.Computed)
	}

	version, ok := resp.Schema.Attributes["userpassword_wo_version"].(resourceschema.Int64Attribute)
	if !ok {
		t.Fatalf("userpassword_wo_version has unexpected schema type %T", resp.Schema.Attributes["userpassword_wo_version"])
	}
	if !version.Optional || version.Sensitive || version.WriteOnly || version.Computed {
		t.Fatalf("unexpected userpassword_wo_version contract: optional=%v sensitive=%v writeOnly=%v computed=%v", version.Optional, version.Sensitive, version.WriteOnly, version.Computed)
	}
}

func TestValidateHostEnrollmentPasswordCreate(t *testing.T) {
	secret := types.StringValue("BIPTEC_TEST_ENROLLMENT_SECRET_DO_NOT_STORE_7f61a2")
	version := types.Int64Value(1)
	if err := validateHostEnrollmentPasswordCreate(secret, version); err != nil {
		t.Fatalf("valid write-only enrollment contract rejected: %v", err)
	}
	if err := validateHostEnrollmentPasswordCreate(secret, types.Int64Null()); err == nil {
		t.Fatal("secret without version must fail")
	}
	if err := validateHostEnrollmentPasswordCreate(types.StringNull(), version); err == nil {
		t.Fatal("version without secret must fail during create")
	}
	if err := validateHostEnrollmentPasswordCreate(types.StringValue(""), version); err == nil {
		t.Fatal("empty secret must fail")
	}
	if err := validateHostEnrollmentPasswordCreate(types.StringNull(), types.Int64Null()); err != nil {
		t.Fatalf("legacy host create without write-only enrollment must remain valid: %v", err)
	}
}

func TestHostEnrollmentPasswordRotation(t *testing.T) {
	secret := types.StringValue("BIPTEC_TEST_ENROLLMENT_SECRET_DO_NOT_STORE_7f61a2")

	rotated, err := hostEnrollmentPasswordRotation(secret, types.Int64Value(2), types.Int64Value(1))
	if err != nil || rotated == nil || *rotated != secret.ValueString() {
		t.Fatalf("expected rotation password, got value=%v err=%v", rotated, err)
	}

	rotated, err = hostEnrollmentPasswordRotation(secret, types.Int64Value(1), types.Int64Value(1))
	if err != nil || rotated != nil {
		t.Fatalf("unchanged version must not rotate password, got value=%v err=%v", rotated, err)
	}

	if _, err = hostEnrollmentPasswordRotation(types.StringNull(), types.Int64Value(2), types.Int64Value(1)); err == nil {
		t.Fatal("version change without secret must fail")
	}
}
