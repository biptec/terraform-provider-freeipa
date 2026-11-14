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

var _ resource.Resource = &ServiceKeytabHostResource{}
var _ resource.ResourceWithImportState = &ServiceKeytabHostResource{}

func NewServiceKeytabHostResource() resource.Resource {
	return &ServiceKeytabHostResource{}
}

type ServiceKeytabHostResource struct {
	client *ipa.Client
	raw    *rawFreeIPAClient
}

type ServiceKeytabHostResourceModel struct {
	ID        types.String `tfsdk:"id"`
	Principal types.String `tfsdk:"principal"`
	Host      types.String `tfsdk:"host"`
}

func (r *ServiceKeytabHostResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_keytab_host"
}

func (r *ServiceKeytabHostResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Allows one FreeIPA host to create and retrieve the keytab of one existing service principal. The keytab material itself is never stored in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true},
			"principal": schema.StringAttribute{
				MarkdownDescription: "Canonical FreeIPA service principal.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"host": schema.StringAttribute{
				MarkdownDescription: "FreeIPA host FQDN allowed to create and retrieve this service keytab.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
	}
}

func (r *ServiceKeytabHostResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*ipa.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected *freeipa.Client, got: %T", req.ProviderData))
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

func (r *ServiceKeytabHostResource) accessState(principal, host string) (retrieve, create bool, err error) {
	service, err := r.raw.serviceKeytabAccessShow(principal)
	if err != nil {
		return false, false, err
	}
	return stringSliceContainsFold(&service.AllowedRetrieveHosts, host),
		stringSliceContainsFold(&service.AllowedCreateHosts, host),
		nil
}

func (r *ServiceKeytabHostResource) ensureAccess(principal, host, kind string) error {
	retrieve, create, err := r.accessState(principal, host)
	if err != nil {
		return err
	}
	present := retrieve
	if kind == "create" {
		present = create
	}
	if present {
		return nil
	}

	mutate := func() (int, ipa.FailedOperations, error) {
		hosts := []string{host}
		switch kind {
		case "retrieve":
			result, err := r.client.ServiceAllowRetrieveKeytab(
				&ipa.ServiceAllowRetrieveKeytabArgs{Krbcanonicalname: principal},
				&ipa.ServiceAllowRetrieveKeytabOptionalArgs{Host: &hosts},
			)
			if err != nil {
				return 0, nil, err
			}
			if result == nil {
				return 0, nil, fmt.Errorf("FreeIPA returned an empty service_allow_retrieve_keytab result")
			}
			return result.Completed, result.Failed, nil
		case "create":
			result, err := r.client.ServiceAllowCreateKeytab(
				&ipa.ServiceAllowCreateKeytabArgs{Krbcanonicalname: principal},
				&ipa.ServiceAllowCreateKeytabOptionalArgs{Host: &hosts},
			)
			if err != nil {
				return 0, nil, err
			}
			if result == nil {
				return 0, nil, fmt.Errorf("FreeIPA returned an empty service_allow_create_keytab result")
			}
			return result.Completed, result.Failed, nil
		default:
			return 0, nil, fmt.Errorf("unknown service keytab access kind %q", kind)
		}
	}
	verify := func() (bool, error) {
		retrieve, create, err := r.accessState(principal, host)
		if err != nil {
			return false, err
		}
		if kind == "create" {
			return create, nil
		}
		return retrieve, nil
	}
	return createPolicyMembership("service", principal, kind+"-keytab host", host, mutate, verify)
}

func (r *ServiceKeytabHostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ServiceKeytabHostResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	principal := strings.TrimSpace(data.Principal.ValueString())
	host := strings.TrimSpace(data.Host.ValueString())
	if principal == "" || host == "" {
		resp.Diagnostics.AddError("Invalid Service Keytab Host", "principal and host must not be empty")
		return
	}
	if err := r.ensureAccess(principal, host, "retrieve"); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error allowing host %q to retrieve keytab for service %q: %s", host, principal, err))
		return
	}
	if err := r.ensureAccess(principal, host, "create"); err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error allowing host %q to create keytab for service %q: %s", host, principal, err))
		return
	}
	data.ID = types.StringValue(principal + "|" + host)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceKeytabHostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ServiceKeytabHostResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	retrieve, create, err := r.accessState(data.Principal.ValueString(), data.Host.ValueString())
	if err != nil {
		if serviceNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading service keytab host access: %s", err))
		return
	}
	if !retrieve || !create {
		resp.State.RemoveResource(ctx)
		return
	}
	data.ID = types.StringValue(data.Principal.ValueString() + "|" + data.Host.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceKeytabHostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unexpected Update", "service keytab host changes require resource replacement")
}

func (r *ServiceKeytabHostResource) removeAccess(principal, host, kind string) error {
	retrieve, create, err := r.accessState(principal, host)
	if err != nil {
		if serviceNotFound(err) {
			return nil
		}
		return err
	}
	present := retrieve
	if kind == "create" {
		present = create
	}
	if !present {
		return nil
	}
	mutate := func() error {
		hosts := []string{host}
		switch kind {
		case "retrieve":
			_, err := r.client.ServiceDisallowRetrieveKeytab(
				&ipa.ServiceDisallowRetrieveKeytabArgs{Krbcanonicalname: principal},
				&ipa.ServiceDisallowRetrieveKeytabOptionalArgs{Host: &hosts},
			)
			return err
		case "create":
			_, err := r.client.ServiceDisallowCreateKeytab(
				&ipa.ServiceDisallowCreateKeytabArgs{Krbcanonicalname: principal},
				&ipa.ServiceDisallowCreateKeytabOptionalArgs{Host: &hosts},
			)
			return err
		default:
			return fmt.Errorf("unknown service keytab access kind %q", kind)
		}
	}
	verify := func() (bool, error) {
		retrieve, create, err := r.accessState(principal, host)
		if err != nil {
			return false, err
		}
		if kind == "create" {
			return create, nil
		}
		return retrieve, nil
	}
	return deletePolicyMembership("service", principal, kind+"-keytab host", host, mutate, verify)
}

func (r *ServiceKeytabHostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ServiceKeytabHostResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	principal := data.Principal.ValueString()
	host := data.Host.ValueString()
	for _, kind := range []string{"create", "retrieve"} {
		if err := r.removeAccess(principal, host, kind); err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing %s keytab access for host %q on service %q: %s", kind, host, principal, err))
			return
		}
	}
}

func (r *ServiceKeytabHostResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	principal, host, err := parseServiceAssociationImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), principal+"|"+host)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("principal"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host"), host)...)
}
