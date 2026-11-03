// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ipa "github.com/infra-monkey/go-freeipa/freeipa"
)

var _ resource.Resource = &ServicePrincipalAliasResource{}
var _ resource.ResourceWithImportState = &ServicePrincipalAliasResource{}

func NewServicePrincipalAliasResource() resource.Resource {
	return &ServicePrincipalAliasResource{}
}

type ServicePrincipalAliasResource struct {
	client *ipa.Client
}

type ServicePrincipalAliasResourceModel struct {
	Id        types.String `tfsdk:"id"`
	Principal types.String `tfsdk:"principal"`
	Alias     types.String `tfsdk:"alias"`
}

func (r *ServicePrincipalAliasResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_principal_alias"
}

func (r *ServicePrincipalAliasResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Associates an additional Kerberos principal alias with an existing FreeIPA service. The service itself remains independently owned.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true},
			"principal": schema.StringAttribute{
				MarkdownDescription: "Canonical FreeIPA service principal, for example HTTP/router.example.test.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"alias": schema.StringAttribute{
				MarkdownDescription: "Additional principal alias to associate with the canonical service.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
	}
}

func (r *ServicePrincipalAliasResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*ipa.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *freeipa.Client, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

func normalizeServicePrincipal(value string) string {
	value = strings.TrimSpace(value)
	if at := strings.LastIndex(value, "@"); at > 0 {
		value = value[:at]
	}
	return value
}

func (r *ServicePrincipalAliasResource) associationExists(principal, alias string) (bool, error) {
	pkeyOnly := true
	noMembers := true
	principalFilter := principal
	aliasFilter := []string{alias}
	res, err := r.client.ServiceFind(
		"",
		&ipa.ServiceFindArgs{},
		&ipa.ServiceFindOptionalArgs{
			Krbcanonicalname: &principalFilter,
			Krbprincipalname: &aliasFilter,
			PkeyOnly:         &pkeyOnly,
			NoMembers:        &noMembers,
		},
	)
	if err != nil {
		if serviceAddResponseDecodeError(err) {
			return true, nil
		}
		return false, err
	}
	for _, service := range res.Result {
		if normalizeServicePrincipal(service.Krbcanonicalname) == normalizeServicePrincipal(principal) {
			return true, nil
		}
	}
	return false, nil
}

func (r *ServicePrincipalAliasResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ServicePrincipalAliasResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	principal := strings.TrimSpace(data.Principal.ValueString())
	alias := strings.TrimSpace(data.Alias.ValueString())
	if principal == "" || alias == "" {
		resp.Diagnostics.AddError("Invalid Service Principal Association", "principal and alias must not be empty")
		return
	}
	if normalizeServicePrincipal(principal) == normalizeServicePrincipal(alias) {
		resp.Diagnostics.AddError("Invalid Service Principal Association", "alias must differ from the canonical principal")
		return
	}
	exists, err := r.associationExists(principal, alias)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA service %s before adding alias %s: %s", principal, alias, err))
		return
	}
	if !exists {
		aliases := []string{alias}
		if _, err := r.client.ServiceAddPrincipal(
			&ipa.ServiceAddPrincipalArgs{Krbcanonicalname: principal, Krbprincipalname: aliases},
			&ipa.ServiceAddPrincipalOptionalArgs{},
		); err != nil {
			if !serviceAddResponseDecodeError(err) {
				resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding alias %s to FreeIPA service %s: %s", alias, principal, err))
				return
			}
			committed, verifyErr := r.associationExists(principal, alias)
			if verifyErr != nil || !committed {
				resp.Diagnostics.AddError("Client Error", fmt.Sprintf("FreeIPA principal alias update for %s -> %s returned an undecodable response (%s) and could not be confirmed: %v", principal, alias, err, verifyErr))
				return
			}
		}
	}
	data.Id = types.StringValue(principal + "|" + alias)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServicePrincipalAliasResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ServicePrincipalAliasResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	principal := data.Principal.ValueString()
	alias := data.Alias.ValueString()
	exists, err := r.associationExists(principal, alias)
	if err != nil {
		if serviceNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading alias %s on FreeIPA service %s: %s", alias, principal, err))
		return
	}
	if !exists {
		resp.State.RemoveResource(ctx)
		return
	}
	data.Id = types.StringValue(principal + "|" + alias)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServicePrincipalAliasResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unexpected Update", "service principal alias changes require resource replacement")
}

func (r *ServicePrincipalAliasResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ServicePrincipalAliasResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	principal := data.Principal.ValueString()
	alias := data.Alias.ValueString()
	exists, err := r.associationExists(principal, alias)
	if err != nil {
		if serviceNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error checking alias %s on FreeIPA service %s before removal: %s", alias, principal, err))
		return
	}
	if !exists {
		return
	}
	aliases := []string{alias}
	_, err = r.client.ServiceRemovePrincipal(
		&ipa.ServiceRemovePrincipalArgs{Krbcanonicalname: principal, Krbprincipalname: aliases},
		&ipa.ServiceRemovePrincipalOptionalArgs{},
	)
	if err != nil && !serviceNotFound(err) {
		if !serviceAddResponseDecodeError(err) {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing alias %s from FreeIPA service %s: %s", alias, principal, err))
			return
		}
		stillExists, verifyErr := r.associationExists(principal, alias)
		if verifyErr != nil || stillExists {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("FreeIPA principal alias removal for %s -> %s returned an undecodable response (%s) and could not be confirmed: %v", principal, alias, err, verifyErr))
		}
	}
}

func parseServiceAssociationImportID(value string) (string, string, error) {
	principal, association, ok := strings.Cut(strings.TrimSpace(value), "|")
	if !ok || strings.TrimSpace(principal) == "" || strings.TrimSpace(association) == "" {
		return "", "", fmt.Errorf("import ID must be <principal>|<association>")
	}
	return strings.TrimSpace(principal), strings.TrimSpace(association), nil
}

func (r *ServicePrincipalAliasResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	principal, alias, err := parseServiceAssociationImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), principal+"|"+alias)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("principal"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("alias"), alias)...)
}
