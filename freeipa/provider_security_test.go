package freeipa

import (
	"fmt"
	"testing"

	ipa "github.com/infra-monkey/go-freeipa/freeipa"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestNormalizeKerberosPrincipal(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		realm     string
		wantName  string
		wantRealm string
		wantErr   bool
	}{
		{name: "full principal", principal: "terraform/runner@EXAMPLE.TEST", wantName: "terraform/runner", wantRealm: "EXAMPLE.TEST"},
		{name: "separate realm", principal: "terraform/runner", realm: "EXAMPLE.TEST", wantName: "terraform/runner", wantRealm: "EXAMPLE.TEST"},
		{name: "matching realm case insensitive", principal: "terraform/runner@example.test", realm: "EXAMPLE.TEST", wantName: "terraform/runner", wantRealm: "EXAMPLE.TEST"},
		{name: "missing principal", realm: "EXAMPLE.TEST", wantErr: true},
		{name: "missing realm", principal: "terraform/runner", wantErr: true},
		{name: "realm mismatch", principal: "terraform/runner@OTHER.TEST", realm: "EXAMPLE.TEST", wantErr: true},
		{name: "empty principal realm", principal: "terraform/runner@", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotRealm, err := normalizeKerberosPrincipal(tt.principal, tt.realm)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got principal=%q realm=%q", gotName, gotRealm)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotName != tt.wantName || gotRealm != tt.wantRealm {
				t.Fatalf("got (%q, %q), want (%q, %q)", gotName, gotRealm, tt.wantName, tt.wantRealm)
			}
		})
	}
}

func TestKerberosConfigured(t *testing.T) {
	empty := &freeipaProviderModel{}
	if kerberosConfigured(empty) {
		t.Fatal("empty provider configuration must use password mode")
	}

	byPrincipal := &freeipaProviderModel{KerberosPrincipal: types.StringValue("terraform/runner@EXAMPLE.TEST")}
	if !kerberosConfigured(byPrincipal) {
		t.Fatal("kerberos principal must select Kerberos mode")
	}

	byKeytab := &freeipaProviderModel{KeytabPath: types.StringValue("/run/secrets/freeipa.keytab")}
	if !kerberosConfigured(byKeytab) {
		t.Fatal("keytab path must select Kerberos mode")
	}
}

func TestValidateFreeIPAClient(t *testing.T) {
	if _, err := validateFreeIPAClient(nil, nil, "Kerberos"); err == nil {
		t.Fatal("nil Kerberos client without an error must be rejected")
	}

	wantErr := fmt.Errorf("authentication failed")
	if _, err := validateFreeIPAClient(nil, wantErr, "Kerberos"); err != wantErr {
		t.Fatalf("expected original error, got %v", err)
	}

	client := &ipa.Client{}
	got, err := validateFreeIPAClient(client, nil, "Kerberos")
	if err != nil || got != client {
		t.Fatalf("valid client rejected: client=%p err=%v", got, err)
	}
}
