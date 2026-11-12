// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	ipa "github.com/infra-monkey/go-freeipa/freeipa"
)

var _ datasource.DataSource = &CertprofileDataSource{}
var _ datasource.DataSourceWithConfigure = &CertprofileDataSource{}

func NewCertprofileDataSource() datasource.DataSource { return &CertprofileDataSource{} }

type CertprofileDataSource struct {
	client *ipa.Client
	raw    *rawFreeIPAClient
}

type CertprofileDataSourceModel struct {
	ID          types.String           `tfsdk:"id"`
	Name        types.String           `tfsdk:"name"`
	Description types.String           `tfsdk:"description"`
	StoreIssued types.Bool             `tfsdk:"store_issued"`
	Config      certprofileConfigValue `tfsdk:"config"`
}

func (d *CertprofileDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certprofile"
}

func (d *CertprofileDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Read a FreeIPA certificate profile, including the complete raw Dogtag profile configuration.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"name": schema.StringAttribute{
				Required: true,
			},
			"description": schema.StringAttribute{
				Computed: true,
			},
			"store_issued": schema.BoolAttribute{
				Computed: true,
			},
			"config": schema.StringAttribute{
				Computed:   true,
				CustomType: certprofileConfigType{},
			},
		},
	}
}

func (d *CertprofileDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*ipa.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type", fmt.Sprintf("Expected *ipa.Client, got %T", req.ProviderData))
		return
	}
	raw, err := rawFreeIPAClientFor(client)
	if err != nil {
		resp.Diagnostics.AddError("Provider Configuration Error", err.Error())
		return
	}
	d.client = client
	d.raw = raw
}

func (d *CertprofileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CertprofileDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	profile, err := d.raw.certprofileShow(data.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA certificate profile %q: %s", data.Name.ValueString(), err))
		return
	}

	data.ID = types.StringValue(profile.Name)
	data.Name = types.StringValue(profile.Name)
	data.Description = types.StringValue(profile.Description)
	data.StoreIssued = types.BoolValue(profile.StoreIssued)
	data.Config = certprofileConfigValueFromString(canonicalCertprofileConfig(profile.Config))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
