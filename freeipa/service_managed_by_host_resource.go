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

var _ resource.Resource = &ServiceManagedByHostResource{}
var _ resource.ResourceWithImportState = &ServiceManagedByHostResource{}

func NewServiceManagedByHostResource() resource.Resource {
	return &ServiceManagedByHostResource{}
}

type ServiceManagedByHostResource struct {
	client *ipa.Client
}

type ServiceManagedByHostResourceModel struct {
	Id        types.String `tfsdk:"id"`
	Principal types.String `tfsdk:"principal"`
	Host      types.String `tfsdk:"host"`
}

func (r *ServiceManagedByHostResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_managed_by_host"
}

func (r *ServiceManagedByHostResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Associates one FreeIPA host with an existing service's managedBy membership. Multiple resource instances can grant management to multiple hosts.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true},
			"principal": schema.StringAttribute{
				MarkdownDescription: "Canonical FreeIPA service principal.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"host": schema.StringAttribute{
				MarkdownDescription: "FreeIPA host FQDN to add to the service managedBy relationship.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
	}
}

func (r *ServiceManagedByHostResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ServiceManagedByHostResource) associationExists(principal, host string) (bool, error) {
	pkeyOnly := true
	noMembers := true
	principalFilter := principal
	hosts := []string{host}
	res, err := r.client.ServiceFind(
		"",
		&ipa.ServiceFindArgs{},
		&ipa.ServiceFindOptionalArgs{
			Krbcanonicalname: &principalFilter,
			ManByHost:        &hosts,
			PkeyOnly:         &pkeyOnly,
			NoMembers:        &noMembers,
		},
	)
	if err != nil {
		return false, err
	}
	for _, service := range res.Result {
		if normalizeServicePrincipal(service.Krbcanonicalname) == normalizeServicePrincipal(principal) {
			return true, nil
		}
	}
	return false, nil
}

func (r *ServiceManagedByHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ServiceManagedByHostResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	principal := strings.TrimSpace(data.Principal.ValueString())
	host := strings.TrimSpace(data.Host.ValueString())
	if principal == "" || host == "" {
		resp.Diagnostics.AddError("Invalid Service managedBy Association", "principal and host must not be empty")
		return
	}
	exists, err := r.associationExists(principal, host)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error checking host %s management of FreeIPA service %s: %s", host, principal, err))
		return
	}
	if !exists {
		hosts := []string{host}
		if _, err := r.client.ServiceAddHost(
			&ipa.ServiceAddHostArgs{Krbcanonicalname: principal},
			&ipa.ServiceAddHostOptionalArgs{Host: &hosts},
		); err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error granting host %s management of FreeIPA service %s: %s", host, principal, err))
			return
		}
	}
	data.Id = types.StringValue(principal + "|" + host)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceManagedByHostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ServiceManagedByHostResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	principal := data.Principal.ValueString()
	host := data.Host.ValueString()
	exists, err := r.associationExists(principal, host)
	if err != nil {
		if serviceNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error checking host %s management of FreeIPA service %s: %s", host, principal, err))
		return
	}
	if !exists {
		resp.State.RemoveResource(ctx)
		return
	}
	data.Id = types.StringValue(principal + "|" + host)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceManagedByHostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unexpected Update", "service managedBy host changes require resource replacement")
}

func (r *ServiceManagedByHostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ServiceManagedByHostResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	principal := data.Principal.ValueString()
	host := data.Host.ValueString()
	exists, err := r.associationExists(principal, host)
	if err != nil {
		if serviceNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error checking host %s management of FreeIPA service %s before removal: %s", host, principal, err))
		return
	}
	if !exists {
		return
	}
	hosts := []string{host}
	_, err = r.client.ServiceRemoveHost(
		&ipa.ServiceRemoveHostArgs{Krbcanonicalname: principal},
		&ipa.ServiceRemoveHostOptionalArgs{Host: &hosts},
	)
	if err != nil && !serviceNotFound(err) {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing host %s management from FreeIPA service %s: %s", host, principal, err))
	}
}

func (r *ServiceManagedByHostResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	principal, host, err := parseServiceAssociationImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), principal+"|"+host)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("principal"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host"), host)...)
}
