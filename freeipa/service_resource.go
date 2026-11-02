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
	"github.com/hashicorp/terraform-plugin-log/tflog"
	ipa "github.com/infra-monkey/go-freeipa/freeipa"
)

var _ resource.Resource = &ServiceResource{}
var _ resource.ResourceWithImportState = &ServiceResource{}

func NewServiceResource() resource.Resource {
	return &ServiceResource{}
}

type ServiceResource struct {
	client *ipa.Client
}

type ServiceResourceModel struct {
	Id            types.String `tfsdk:"id"`
	Principal     types.String `tfsdk:"principal"`
	ManagedByHost types.String `tfsdk:"managed_by_host"`
	Force         types.Bool   `tfsdk:"force"`
	SkipHostCheck types.Bool   `tfsdk:"skip_host_check"`
}

func (r *ServiceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

func (r *ServiceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "FreeIPA Kerberos service principal resource. Manages the service identity and an optional host allowed to manage it. Certificate/private-key material is not stored by this resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "ID of the resource.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"principal": schema.StringAttribute{
				MarkdownDescription: "Service principal in FreeIPA CLI/API form, for example HTTP/app.example.test.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"managed_by_host": schema.StringAttribute{
				MarkdownDescription: "Optional FreeIPA host FQDN allowed to manage this service. Maps to service-add-host / managedBy.",
				Optional:            true,
				Computed:            true,
			},
			"force": schema.BoolAttribute{
				MarkdownDescription: "Force service creation when the service hostname is not resolvable in DNS.",
				Optional:            true,
			},
			"skip_host_check": schema.BoolAttribute{
				MarkdownDescription: "Allow creation when the service hostname does not correspond to an existing FreeIPA host object.",
				Optional:            true,
			},
		},
	}
}

func (r *ServiceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*ipa.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *freeipa.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = client
}

func serviceNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "NotFound")
}

func (r *ServiceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ServiceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	principal := strings.TrimSpace(data.Principal.ValueString())
	if principal == "" {
		resp.Diagnostics.AddError("Invalid Service Principal", "principal must not be empty")
		return
	}

	all := true
	force := data.Force.ValueBool()
	skipHostCheck := data.SkipHostCheck.ValueBool()
	ret, err := r.client.ServiceAdd(
		&ipa.ServiceAddArgs{Krbcanonicalname: principal},
		&ipa.ServiceAddOptionalArgs{
			All:           &all,
			Force:         &force,
			SkipHostCheck: &skipHostCheck,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error creating FreeIPA service %s: %s", principal, err))
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("[DEBUG] Create FreeIPA service returned %s", ret.String()))

	if !data.ManagedByHost.IsNull() && !data.ManagedByHost.IsUnknown() {
		host := strings.TrimSpace(data.ManagedByHost.ValueString())
		if host != "" {
			hosts := []string{host}
			if _, err := r.client.ServiceAddHost(
				&ipa.ServiceAddHostArgs{Krbcanonicalname: principal},
				&ipa.ServiceAddHostOptionalArgs{Host: &hosts},
			); err != nil {
				_, _ = r.client.ServiceDel(
					&ipa.ServiceDelArgs{Krbcanonicalname: []string{principal}},
					&ipa.ServiceDelOptionalArgs{},
				)
				resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error granting host %s management of FreeIPA service %s: %s", host, principal, err))
				return
			}
		}
	}

	data.Id = types.StringValue(principal)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ServiceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	principal := data.Principal.ValueString()
	all := true
	raw := true
	res, err := r.client.ServiceShow(
		&ipa.ServiceShowArgs{Krbcanonicalname: principal},
		&ipa.ServiceShowOptionalArgs{All: &all, Raw: &raw},
	)
	if err != nil {
		if serviceNotFound(err) {
			tflog.Debug(ctx, fmt.Sprintf("[DEBUG] FreeIPA service %s not found, removing from state", principal))
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA service %s: %s", principal, err))
		return
	}

	if res.Result.ManagedbyHost != "" {
		data.ManagedByHost = types.StringValue(res.Result.ManagedbyHost)
	} else {
		data.ManagedByHost = types.StringNull()
	}
	data.Id = types.StringValue(principal)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data, state ServiceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	principal := data.Principal.ValueString()
	oldHost := ""
	if !state.ManagedByHost.IsNull() && !state.ManagedByHost.IsUnknown() {
		oldHost = strings.TrimSpace(state.ManagedByHost.ValueString())
	}
	newHost := ""
	if !data.ManagedByHost.IsNull() && !data.ManagedByHost.IsUnknown() {
		newHost = strings.TrimSpace(data.ManagedByHost.ValueString())
	}

	if oldHost != newHost {
		if newHost != "" {
			hosts := []string{newHost}
			if _, err := r.client.ServiceAddHost(
				&ipa.ServiceAddHostArgs{Krbcanonicalname: principal},
				&ipa.ServiceAddHostOptionalArgs{Host: &hosts},
			); err != nil {
				resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error granting host %s management of FreeIPA service %s: %s", newHost, principal, err))
				return
			}
		}
		if oldHost != "" {
			hosts := []string{oldHost}
			if _, err := r.client.ServiceRemoveHost(
				&ipa.ServiceRemoveHostArgs{Krbcanonicalname: principal},
				&ipa.ServiceRemoveHostOptionalArgs{Host: &hosts},
			); err != nil {
				resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing host %s from FreeIPA service %s: %s", oldHost, principal, err))
				return
			}
		}
	}

	data.Id = types.StringValue(principal)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ServiceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	principal := data.Principal.ValueString()
	_, err := r.client.ServiceDel(
		&ipa.ServiceDelArgs{Krbcanonicalname: []string{principal}},
		&ipa.ServiceDelOptionalArgs{},
	)
	if err != nil && !serviceNotFound(err) {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error deleting FreeIPA service %s: %s", principal, err))
	}
}

func (r *ServiceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	principal := strings.TrimSpace(req.ID)
	if principal == "" {
		resp.Diagnostics.AddError("Import Error", "service principal import ID must not be empty")
		return
	}

	all := true
	raw := true
	if _, err := r.client.ServiceShow(
		&ipa.ServiceShowArgs{Krbcanonicalname: principal},
		&ipa.ServiceShowOptionalArgs{All: &all, Raw: &raw},
	); err != nil {
		resp.Diagnostics.AddError("Import Error", fmt.Sprintf("Error reading FreeIPA service %s: %s", principal, err))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("principal"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("force"), false)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("skip_host_check"), false)...)
}
