// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ipa "github.com/infra-monkey/go-freeipa/freeipa"
)

var _ resource.Resource = &CAACLResource{}
var _ resource.ResourceWithImportState = &CAACLResource{}

func NewCAACLResource() resource.Resource { return &CAACLResource{} }

type CAACLResource struct {
	client *ipa.Client
	raw    *rawFreeIPAClient
}

type CAACLResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	CACategory      types.String `tfsdk:"ca_category"`
	ProfileCategory types.String `tfsdk:"profile_category"`
	UserCategory    types.String `tfsdk:"user_category"`
	HostCategory    types.String `tfsdk:"host_category"`
	ServiceCategory types.String `tfsdk:"service_category"`
}

func (r *CAACLResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca_acl"
}

func (r *CAACLResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "FreeIPA CA ACL resource. Memberships are managed by dedicated membership resources.",
		Attributes: map[string]schema.Attribute{
			"id":               schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":             schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"description":      schema.StringAttribute{Optional: true},
			"enabled":          schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"ca_category":      schema.StringAttribute{Optional: true},
			"profile_category": schema.StringAttribute{Optional: true},
			"user_category":    schema.StringAttribute{Optional: true},
			"host_category":    schema.StringAttribute{Optional: true},
			"service_category": schema.StringAttribute{Optional: true},
		},
	}
}

func (r *CAACLResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func caACLFromModel(data *CAACLResourceModel) rawCAACL {
	stringValue := func(value types.String) string {
		if value.IsNull() || value.IsUnknown() {
			return ""
		}
		return value.ValueString()
	}
	return rawCAACL{
		Name:            data.Name.ValueString(),
		Description:     stringValue(data.Description),
		Enabled:         data.Enabled.ValueBool(),
		CACategory:      stringValue(data.CACategory),
		ProfileCategory: stringValue(data.ProfileCategory),
		UserCategory:    stringValue(data.UserCategory),
		HostCategory:    stringValue(data.HostCategory),
		ServiceCategory: stringValue(data.ServiceCategory),
	}
}

func caACLModelString(value string) types.String {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}

func (r *CAACLResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CAACLResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.raw.caACLAdd(caACLFromModel(&data))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error creating FreeIPA CA ACL %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CAACLResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CAACLResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	acl, err := r.raw.caACLShow(data.Name.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA CA ACL %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = types.StringValue(acl.Name)
	data.Name = types.StringValue(acl.Name)
	data.Description = caACLModelString(acl.Description)
	data.Enabled = types.BoolValue(acl.Enabled)
	data.CACategory = caACLModelString(acl.CACategory)
	data.ProfileCategory = caACLModelString(acl.ProfileCategory)
	data.UserCategory = caACLModelString(acl.UserCategory)
	data.HostCategory = caACLModelString(acl.HostCategory)
	data.ServiceCategory = caACLModelString(acl.ServiceCategory)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CAACLResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data, state CAACLResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	changes := map[string]any{}
	setString := func(key string, cur, old types.String) {
		if cur.Equal(old) {
			return
		}
		value := ""
		if !cur.IsNull() && !cur.IsUnknown() {
			value = cur.ValueString()
		}
		changes[key] = value
	}
	setString("description", data.Description, state.Description)
	if !data.Enabled.Equal(state.Enabled) {
		changes["ipaenabledflag"] = data.Enabled.ValueBool()
	}
	setString("ipacacategory", data.CACategory, state.CACategory)
	setString("ipacertprofilecategory", data.ProfileCategory, state.ProfileCategory)
	setString("usercategory", data.UserCategory, state.UserCategory)
	setString("hostcategory", data.HostCategory, state.HostCategory)
	setString("servicecategory", data.ServiceCategory, state.ServiceCategory)
	if len(changes) > 0 {
		if err := r.raw.caACLMod(data.Name.ValueString(), changes); err != nil && !strings.Contains(err.Error(), "EmptyModlist") {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error updating FreeIPA CA ACL %q: %s", data.Name.ValueString(), err))
			return
		}
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CAACLResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CAACLResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.raw.caACLDel(data.Name.ValueString())
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error deleting FreeIPA CA ACL %q: %s", data.Name.ValueString(), err))
	}
}

func (r *CAACLResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if name == "" {
		resp.Diagnostics.AddError("Import Error", "CA ACL import ID must not be empty")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}
