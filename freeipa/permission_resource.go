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

var _ resource.Resource = &PermissionResource{}
var _ resource.ResourceWithImportState = &PermissionResource{}

func NewPermissionResource() resource.Resource { return &PermissionResource{} }

type PermissionResource struct {
	client *ipa.Client
	raw    *rawFreeIPAClient
}

type PermissionResourceModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Rights             types.Set    `tfsdk:"rights"`
	IncludedAttributes types.Set    `tfsdk:"included_attributes"`
	Target             types.String `tfsdk:"target"`
}

func (r *PermissionResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_permission"
}

func (r *PermissionResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "FreeIPA permission resource. Manages the permission identity, owner description, granted rights, included attributes and explicit target DN.",
		Attributes: map[string]schema.Attribute{
			"id":                  schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":                schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"description":         schema.StringAttribute{Required: true},
			"rights":              schema.SetAttribute{Required: true, ElementType: types.StringType},
			"included_attributes": schema.SetAttribute{Required: true, ElementType: types.StringType},
			"target":              schema.StringAttribute{Required: true},
		},
	}
}

func (r *PermissionResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*ipa.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *ipa.Client, got %T", req.ProviderData))
		return
	}
	raw, err := rawFreeIPAClientFor(client)
	if err != nil {
		resp.Diagnostics.AddError("Provider Configuration Error", err.Error())
		return
	}
	r.client = client
	r.raw = raw
}

func setToStrings(ctx context.Context, value types.Set) ([]string, error) {
	var out []string
	diags := value.ElementsAs(ctx, &out, false)
	if diags.HasError() {
		return nil, fmt.Errorf("%s", diags.Errors()[0].Detail())
	}
	return out, nil
}

func permissionFromModel(ctx context.Context, data *PermissionResourceModel) (rawPermission, error) {
	rights, err := setToStrings(ctx, data.Rights)
	if err != nil {
		return rawPermission{}, err
	}
	attrs, err := setToStrings(ctx, data.IncludedAttributes)
	if err != nil {
		return rawPermission{}, err
	}
	return rawPermission{
		Name:               data.Name.ValueString(),
		Description:        data.Description.ValueString(),
		Rights:             rights,
		IncludedAttributes: attrs,
		Target:             data.Target.ValueString(),
	}, nil
}

func (r *PermissionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PermissionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	permission, err := permissionFromModel(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddError("Configuration Error", err.Error())
		return
	}
	if err := r.raw.permissionAdd(permission); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error creating FreeIPA permission %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PermissionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PermissionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	permission, err := r.raw.permissionShow(data.Name.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA permission %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = types.StringValue(permission.Name)
	data.Name = types.StringValue(permission.Name)
	data.Description = types.StringValue(permission.Description)
	rights, diags := types.SetValueFrom(ctx, types.StringType, permission.Rights)
	resp.Diagnostics.Append(diags...)
	data.Rights = rights
	attrs, diags := types.SetValueFrom(ctx, types.StringType, permission.IncludedAttributes)
	resp.Diagnostics.Append(diags...)
	data.IncludedAttributes = attrs
	data.Target = types.StringValue(permission.Target)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PermissionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data, state PermissionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !data.Description.Equal(state.Description) ||
		!data.Rights.Equal(state.Rights) ||
		!data.IncludedAttributes.Equal(state.IncludedAttributes) ||
		!data.Target.Equal(state.Target) {
		permission, err := permissionFromModel(ctx, &data)
		if err != nil {
			resp.Diagnostics.AddError("Configuration Error", err.Error())
			return
		}
		if err := r.raw.permissionMod(permission); err != nil && !strings.Contains(err.Error(), "EmptyModlist") {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error updating FreeIPA permission %q: %s", data.Name.ValueString(), err))
			return
		}
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PermissionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PermissionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.raw.permissionDel(data.Name.ValueString()); err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error deleting FreeIPA permission %q: %s", data.Name.ValueString(), err))
	}
}

func (r *PermissionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if name == "" {
		resp.Diagnostics.AddError("Import Error", "permission import ID must not be empty")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}
