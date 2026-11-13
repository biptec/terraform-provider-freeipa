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

var _ resource.Resource = &HbacServiceResource{}
var _ resource.ResourceWithImportState = &HbacServiceResource{}

func NewHbacServiceResource() resource.Resource {
	return &HbacServiceResource{}
}

type HbacServiceResource struct {
	client *ipa.Client
}

type HbacServiceResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

func (r *HbacServiceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hbac_service"
}

func (r *HbacServiceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "FreeIPA HBAC service resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
		},
	}
}

func (r *HbacServiceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *HbacServiceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data HbacServiceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	opt := ipa.HbacsvcAddOptionalArgs{}
	if !data.Description.IsNull() {
		opt.Description = data.Description.ValueStringPointer()
	}
	_, err := r.client.HbacsvcAdd(&ipa.HbacsvcAddArgs{Cn: data.Name.ValueString()}, &opt)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error creating FreeIPA HBAC service %q: %s", data.Name.ValueString(), err))
		return
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *HbacServiceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data HbacServiceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	all := true
	res, err := r.client.HbacsvcShow(&ipa.HbacsvcShowArgs{Cn: data.Name.ValueString()}, &ipa.HbacsvcShowOptionalArgs{All: &all})
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA HBAC service %q: %s", data.Name.ValueString(), err))
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

func (r *HbacServiceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data, state HbacServiceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !data.Description.Equal(state.Description) {
		opt := ipa.HbacsvcModOptionalArgs{}
		if data.Description.IsNull() {
			empty := ""
			opt.Description = &empty
		} else {
			opt.Description = data.Description.ValueStringPointer()
		}
		_, err := r.client.HbacsvcMod(&ipa.HbacsvcModArgs{Cn: data.Name.ValueString()}, &opt)
		if err != nil && !strings.Contains(err.Error(), "EmptyModlist") {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error updating FreeIPA HBAC service %q: %s", data.Name.ValueString(), err))
			return
		}
	}
	data.ID = data.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *HbacServiceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data HbacServiceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.HbacsvcDel(&ipa.HbacsvcDelArgs{Cn: []string{data.Name.ValueString()}}, &ipa.HbacsvcDelOptionalArgs{})
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error deleting FreeIPA HBAC service %q: %s", data.Name.ValueString(), err))
	}
}

func (r *HbacServiceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := strings.TrimSpace(req.ID)
	if name == "" {
		resp.Diagnostics.AddError("Import Error", "HBAC service import ID must not be empty")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
}
