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

var _ resource.Resource = &RoleResource{}
var _ resource.ResourceWithImportState = &RoleResource{}

func NewRoleResource() resource.Resource { return &RoleResource{} }

type RoleResource struct{ client *ipa.Client }

type RoleResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

func (r *RoleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *RoleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "FreeIPA role resource.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":        schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"description": schema.StringAttribute{Optional: true},
		},
	}
}

func (r *RoleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*ipa.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *ipa.Client, got %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *RoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RoleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	opt := ipa.RoleAddOptionalArgs{}
	if !data.Description.IsNull() {
		opt.Description = data.Description.ValueStringPointer()
	}
	_, err := r.client.RoleAdd(&ipa.RoleAddArgs{Cn: data.Name.ValueString()}, &opt)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error creating FreeIPA role %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RoleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	all := true
	res, err := r.client.RoleShow(&ipa.RoleShowArgs{Cn: data.Name.ValueString()}, &ipa.RoleShowOptionalArgs{All: &all})
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA role %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = types.StringValue(res.Result.Cn)
	data.Name = types.StringValue(res.Result.Cn)
	if res.Result.Description != nil {
		data.Description = types.StringValue(*res.Result.Description)
	} else {
		data.Description = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data, state RoleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !data.Description.Equal(state.Description) {
		opt := ipa.RoleModOptionalArgs{}
		if data.Description.IsNull() {
			empty := ""
			opt.Description = &empty
		} else {
			opt.Description = data.Description.ValueStringPointer()
		}
		_, err := r.client.RoleMod(&ipa.RoleModArgs{Cn: data.Name.ValueString()}, &opt)
		if err != nil && !strings.Contains(err.Error(), "EmptyModlist") {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error updating FreeIPA role %q: %s", data.Name.ValueString(), err))
			return
		}
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RoleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.RoleDel(&ipa.RoleDelArgs{Cn: []string{data.Name.ValueString()}}, &ipa.RoleDelOptionalArgs{})
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error deleting FreeIPA role %q: %s", data.Name.ValueString(), err))
	}
}

func (r *RoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if name == "" {
		resp.Diagnostics.AddError("Import Error", "role import ID must not be empty")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}
