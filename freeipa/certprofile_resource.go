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

var _ resource.Resource = &CertprofileResource{}
var _ resource.ResourceWithImportState = &CertprofileResource{}

func NewCertprofileResource() resource.Resource { return &CertprofileResource{} }

type CertprofileResource struct {
	client *ipa.Client
	raw    *rawFreeIPAClient
}

func canonicalCertprofileConfig(value string) string {
	if value == "" {
		return ""
	}
	return strings.TrimRight(value, "\r\n") + "\n"
}

type CertprofileResourceModel struct {
	ID          types.String           `tfsdk:"id"`
	Name        types.String           `tfsdk:"name"`
	Description types.String           `tfsdk:"description"`
	StoreIssued types.Bool             `tfsdk:"store_issued"`
	Config      certprofileConfigValue `tfsdk:"config"`
}

func (r *CertprofileResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certprofile"
}

func (r *CertprofileResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "FreeIPA certificate profile resource. The config attribute contains the complete raw Dogtag profile configuration managed by FreeIPA.",
		Attributes: map[string]schema.Attribute{
			"id":           schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":         schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"description":  schema.StringAttribute{Required: true},
			"store_issued": schema.BoolAttribute{Required: true},
			"config": schema.StringAttribute{
				Required:   true,
				CustomType: certprofileConfigType{},
			},
		},
	}
}

func (r *CertprofileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func certprofileFromModel(data *CertprofileResourceModel) rawCertprofile {
	return rawCertprofile{
		Name:        data.Name.ValueString(),
		Description: data.Description.ValueString(),
		StoreIssued: data.StoreIssued.ValueBool(),
		Config:      canonicalCertprofileConfig(data.Config.ValueString()),
	}
}

func (r *CertprofileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CertprofileResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.raw.certprofileImport(certprofileFromModel(&data))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error creating FreeIPA certificate profile %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CertprofileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CertprofileResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	profile, err := r.raw.certprofileShow(data.Name.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA certificate profile %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = types.StringValue(profile.Name)
	data.Name = types.StringValue(profile.Name)
	data.Description = types.StringValue(profile.Description)
	data.Config = certprofileConfigValueFromString(canonicalCertprofileConfig(profile.Config))
	data.StoreIssued = types.BoolValue(profile.StoreIssued)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CertprofileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data, state CertprofileResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !data.Description.Equal(state.Description) ||
		!data.StoreIssued.Equal(state.StoreIssued) ||
		!data.Config.Equal(state.Config) {
		if err := r.raw.certprofileMod(certprofileFromModel(&data)); err != nil && !strings.Contains(err.Error(), "EmptyModlist") {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error updating FreeIPA certificate profile %q: %s", data.Name.ValueString(), err))
			return
		}
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CertprofileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CertprofileResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.raw.certprofileDel(data.Name.ValueString())
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error deleting FreeIPA certificate profile %q: %s", data.Name.ValueString(), err))
	}
}

func (r *CertprofileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if name == "" {
		resp.Diagnostics.AddError("Import Error", "certificate profile import ID must not be empty")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}
