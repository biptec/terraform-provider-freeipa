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

var _ datasource.DataSource = &ServiceDataSource{}
var _ datasource.DataSourceWithConfigure = &ServiceDataSource{}

func NewServiceDataSource() datasource.DataSource { return &ServiceDataSource{} }

type ServiceDataSource struct {
	client *ipa.Client
	raw    *rawFreeIPAClient
}

type ServiceDataSourceModel struct {
	ID        types.String `tfsdk:"id"`
	Principal types.String `tfsdk:"principal"`
	DN        types.String `tfsdk:"dn"`
}

func (d *ServiceDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

func (d *ServiceDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Read FreeIPA metadata for a Kerberos service principal.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"principal": schema.StringAttribute{
				Required: true,
			},
			"dn": schema.StringAttribute{
				MarkdownDescription: "LDAP distinguished name of the FreeIPA service entry.",
				Computed:            true,
			},
		},
	}
}

func (d *ServiceDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *ServiceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ServiceDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	service, err := d.raw.serviceShow(data.Principal.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA service %q: %s", data.Principal.ValueString(), err))
		return
	}
	data.ID = data.Principal
	data.DN = types.StringValue(service.DN)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
