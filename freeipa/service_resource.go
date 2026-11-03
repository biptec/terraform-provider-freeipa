// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"context"
	"errors"
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
	AdoptExisting types.Bool   `tfsdk:"adopt_existing"`
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
			"adopt_existing": schema.BoolAttribute{
				MarkdownDescription: "Adopt an already-existing canonical FreeIPA service with the same principal during resource creation instead of failing with a duplicate-entry error. This is intended for controlled migration of legacy service identities into Terraform ownership; aliases are not adopted as canonical services.",
				Optional:            true,
			},
			"force": schema.BoolAttribute{
				MarkdownDescription: "Force service creation when the service hostname is not resolvable in DNS. This option is consumed only when the remote service must be created; changing it for an existing/adopted service updates Terraform state without replacing the FreeIPA service.",
				Optional:            true,
			},
			"skip_host_check": schema.BoolAttribute{
				MarkdownDescription: "Allow creation when the service hostname does not correspond to an existing FreeIPA host object. This option is consumed only when the remote service must be created; changing it for an existing/adopted service updates Terraform state without replacing the FreeIPA service.",
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

func serviceAddResponseDecodeError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *ipa.Error
	if errors.As(err, &apiErr) {
		return false
	}
	return strings.Contains(err.Error(), "unexpected value for field")
}

func serviceExists(client *ipa.Client, principal string) (bool, error) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return false, nil
	}
	pkeyOnly := true
	noMembers := true
	principalFilter := principal
	res, err := client.ServiceFind(
		"",
		&ipa.ServiceFindArgs{},
		&ipa.ServiceFindOptionalArgs{
			Krbcanonicalname: &principalFilter,
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

	exists, err := serviceExists(r.client, principal)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error checking whether FreeIPA service %s already exists: %s", principal, err))
		return
	}

	if exists {
		if !data.AdoptExisting.ValueBool() {
			resp.Diagnostics.AddError(
				"FreeIPA Service Already Exists",
				fmt.Sprintf("FreeIPA service %s already exists outside this Terraform state. Import it explicitly or set adopt_existing=true for a controlled migration into Terraform ownership.", principal),
			)
			return
		}
		tflog.Info(ctx, fmt.Sprintf("[INFO] Adopting existing FreeIPA service %s into Terraform ownership", principal))
	} else {
		force := data.Force.ValueBool()
		skipHostCheck := data.SkipHostCheck.ValueBool()
		ret, err := r.client.ServiceAdd(
			&ipa.ServiceAddArgs{Krbcanonicalname: principal},
			&ipa.ServiceAddOptionalArgs{
				Force:         &force,
				SkipHostCheck: &skipHostCheck,
			},
		)
		if err != nil {
			if serviceAddResponseDecodeError(err) {
				committed, verifyErr := serviceExists(r.client, principal)
				if verifyErr != nil {
					resp.Diagnostics.AddError(
						"Client Error",
						fmt.Sprintf("FreeIPA service %s returned an undecodable create response (%s) and post-create verification failed: %s", principal, err, verifyErr),
					)
					return
				}
				if committed {
					tflog.Warn(ctx, fmt.Sprintf("[WARN] FreeIPA service %s create response was undecodable but service_find confirmed the create committed: %s", principal, err))
				} else {
					resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error creating FreeIPA service %s: %s", principal, err))
					return
				}
			} else {
				resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error creating FreeIPA service %s: %s", principal, err))
				return
			}
		} else {
			tflog.Debug(ctx, fmt.Sprintf("[DEBUG] Create FreeIPA service returned %s", ret.String()))
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
	exists, err := serviceExists(r.client, principal)
	if err != nil {
		if serviceNotFound(err) {
			tflog.Debug(ctx, fmt.Sprintf("[DEBUG] FreeIPA service %s not found, removing from state", principal))
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading FreeIPA service %s: %s", principal, err))
		return
	}
	if !exists {
		tflog.Debug(ctx, fmt.Sprintf("[DEBUG] FreeIPA service %s not found, removing from state", principal))
		resp.State.RemoveResource(ctx)
		return
	}
	data.Id = types.StringValue(principal)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ServiceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// principal requires replacement. adopt_existing, force and skip_host_check
	// are ownership/create-time controls only; updating them must never destroy
	// and recreate an already-existing/adopted FreeIPA service.
	data.Id = types.StringValue(data.Principal.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ServiceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ServiceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	principal := data.Principal.ValueString()
	exists, err := serviceExists(r.client, principal)
	if err != nil {
		if serviceNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error checking FreeIPA service %s before deletion: %s", principal, err))
		return
	}
	if !exists {
		return
	}
	_, err = r.client.ServiceDel(
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

	exists, err := serviceExists(r.client, principal)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", fmt.Sprintf("Error reading FreeIPA service %s: %s", principal, err))
		return
	}
	if !exists {
		resp.Diagnostics.AddError("Import Error", fmt.Sprintf("FreeIPA service %s does not exist", principal))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("principal"), principal)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("adopt_existing"), false)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("force"), false)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("skip_host_check"), false)...)
}
