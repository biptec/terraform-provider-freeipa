// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var (
	_ basetypes.StringTypable                    = certprofileConfigType{}
	_ basetypes.StringValuableWithSemanticEquals = certprofileConfigValue{}
)

type certprofileConfigType struct {
	basetypes.StringType
}

func (t certprofileConfigType) Equal(other attr.Type) bool {
	_, ok := other.(certprofileConfigType)
	return ok
}

func (t certprofileConfigType) String() string {
	return "certprofileConfigType"
}

func (t certprofileConfigType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return certprofileConfigValue{StringValue: in}, nil
}

func (t certprofileConfigType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	value, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	stringValue, ok := value.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected certificate profile config value type %T", value)
	}
	return certprofileConfigValue{StringValue: stringValue}, nil
}

func (t certprofileConfigType) ValueType(context.Context) attr.Value {
	return certprofileConfigValue{}
}

type certprofileConfigValue struct {
	basetypes.StringValue
}

func (v certprofileConfigValue) Equal(other attr.Value) bool {
	otherValue, ok := other.(certprofileConfigValue)
	if !ok {
		return false
	}
	return v.StringValue.Equal(otherValue.StringValue)
}

func (v certprofileConfigValue) StringSemanticEquals(_ context.Context, other basetypes.StringValuable) (bool, diag.Diagnostics) {
	otherValue, ok := other.(certprofileConfigValue)
	if !ok {
		return false, nil
	}
	if v.IsNull() || v.IsUnknown() || otherValue.IsNull() || otherValue.IsUnknown() {
		return v.Equal(otherValue), nil
	}
	return canonicalCertprofileConfig(v.ValueString()) == canonicalCertprofileConfig(otherValue.ValueString()), nil
}

func (v certprofileConfigValue) Type(context.Context) attr.Type {
	return certprofileConfigType{}
}

func certprofileConfigValueFromString(value string) certprofileConfigValue {
	return certprofileConfigValue{StringValue: basetypes.NewStringValue(value)}
}
