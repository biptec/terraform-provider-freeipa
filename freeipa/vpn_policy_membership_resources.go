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

func policyMembershipID(parent, member string) string {
	return encodeSlash(parent) + "/" + encodeSlash(member)
}

func parsePolicyMembershipID(id string) (string, string, error) {
	parts := strings.SplitN(id, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("membership import ID must be escaped-parent/escaped-member")
	}
	return decodeSlash(parts[0]), decodeSlash(parts[1]), nil
}

func stringSliceContainsFold(values *[]string, want string) bool {
	if values == nil {
		return false
	}
	for _, value := range *values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func servicePrincipalEquivalent(actual, want string) bool {
	stripRealm := func(value string) string {
		value = strings.TrimSpace(value)
		if at := strings.LastIndex(value, "@"); at >= 0 {
			value = value[:at]
		}
		return value
	}
	return strings.EqualFold(stripRealm(actual), stripRealm(want))
}

func stringSliceContainsServicePrincipal(values []string, want string) bool {
	for _, value := range values {
		if servicePrincipalEquivalent(value, want) {
			return true
		}
	}
	return false
}

// ---- CA ACL profile membership ----

var _ resource.Resource = &CAACLProfileMembershipResource{}
var _ resource.ResourceWithImportState = &CAACLProfileMembershipResource{}

func NewCAACLProfileMembershipResource() resource.Resource { return &CAACLProfileMembershipResource{} }

type CAACLProfileMembershipResource struct {
	client *ipa.Client
	raw    *rawFreeIPAClient
}

type CAACLProfileMembershipResourceModel struct {
	ID      types.String `tfsdk:"id"`
	CAACL   types.String `tfsdk:"ca_acl"`
	Profile types.String `tfsdk:"profile"`
}

func (r *CAACLProfileMembershipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca_acl_profile_membership"
}

func (r *CAACLProfileMembershipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Membership of one certificate profile in one FreeIPA CA ACL.",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"ca_acl":  schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"profile": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *CAACLProfileMembershipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *CAACLProfileMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CAACLProfileMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.raw.caACLAddProfile(data.CAACL.ValueString(), data.Profile.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding certificate profile %q to CA ACL %q: %s", data.Profile.ValueString(), data.CAACL.ValueString(), err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.CAACL.ValueString(), data.Profile.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CAACLProfileMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CAACLProfileMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	acl, err := r.raw.caACLShow(data.CAACL.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading CA ACL %q: %s", data.CAACL.ValueString(), err))
		return
	}
	if !stringSliceContainsFold(&acl.Profiles, data.Profile.ValueString()) {
		resp.State.RemoveResource(ctx)
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.CAACL.ValueString(), data.Profile.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CAACLProfileMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *CAACLProfileMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CAACLProfileMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.raw.caACLRemoveProfile(data.CAACL.ValueString(), data.Profile.ValueString())
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing certificate profile %q from CA ACL %q: %s", data.Profile.ValueString(), data.CAACL.ValueString(), err))
	}
}

func (r *CAACLProfileMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parent, member, err := parsePolicyMembershipID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), policyMembershipID(parent, member))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ca_acl"), parent)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("profile"), member)...)
}

// ---- CA ACL service membership ----

var _ resource.Resource = &CAACLServiceMembershipResource{}
var _ resource.ResourceWithImportState = &CAACLServiceMembershipResource{}

func NewCAACLServiceMembershipResource() resource.Resource { return &CAACLServiceMembershipResource{} }

type CAACLServiceMembershipResource struct {
	client *ipa.Client
	raw    *rawFreeIPAClient
}

type CAACLServiceMembershipResourceModel struct {
	ID      types.String `tfsdk:"id"`
	CAACL   types.String `tfsdk:"ca_acl"`
	Service types.String `tfsdk:"service"`
}

func (r *CAACLServiceMembershipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca_acl_service_membership"
}

func (r *CAACLServiceMembershipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Membership of one service principal in one FreeIPA CA ACL.",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"ca_acl":  schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"service": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *CAACLServiceMembershipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *CAACLServiceMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CAACLServiceMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.raw.caACLAddService(data.CAACL.ValueString(), data.Service.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding service %q to CA ACL %q: %s", data.Service.ValueString(), data.CAACL.ValueString(), err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.CAACL.ValueString(), data.Service.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CAACLServiceMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CAACLServiceMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	acl, err := r.raw.caACLShow(data.CAACL.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading CA ACL %q: %s", data.CAACL.ValueString(), err))
		return
	}
	if !stringSliceContainsServicePrincipal(acl.Services, data.Service.ValueString()) {
		resp.State.RemoveResource(ctx)
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.CAACL.ValueString(), data.Service.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CAACLServiceMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *CAACLServiceMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CAACLServiceMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.raw.caACLRemoveService(data.CAACL.ValueString(), data.Service.ValueString())
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing service %q from CA ACL %q: %s", data.Service.ValueString(), data.CAACL.ValueString(), err))
	}
}

func (r *CAACLServiceMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parent, member, err := parsePolicyMembershipID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), policyMembershipID(parent, member))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ca_acl"), parent)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service"), member)...)
}

// ---- Privilege permission membership ----

var _ resource.Resource = &PrivilegePermissionMembershipResource{}
var _ resource.ResourceWithImportState = &PrivilegePermissionMembershipResource{}

func NewPrivilegePermissionMembershipResource() resource.Resource {
	return &PrivilegePermissionMembershipResource{}
}

type PrivilegePermissionMembershipResource struct{ client *ipa.Client }

type PrivilegePermissionMembershipResourceModel struct {
	ID         types.String `tfsdk:"id"`
	Privilege  types.String `tfsdk:"privilege"`
	Permission types.String `tfsdk:"permission"`
}

func (r *PrivilegePermissionMembershipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_privilege_permission_membership"
}

func (r *PrivilegePermissionMembershipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Membership of one permission in one FreeIPA privilege.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"privilege":  schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"permission": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *PrivilegePermissionMembershipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *PrivilegePermissionMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PrivilegePermissionMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	permissions := []string{data.Permission.ValueString()}
	_, err := r.client.PrivilegeAddPermission(&ipa.PrivilegeAddPermissionArgs{Cn: data.Privilege.ValueString()}, &ipa.PrivilegeAddPermissionOptionalArgs{Permission: &permissions})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding permission %q to privilege %q: %s", data.Permission.ValueString(), data.Privilege.ValueString(), err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.Privilege.ValueString(), data.Permission.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PrivilegePermissionMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PrivilegePermissionMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	all := true
	res, err := r.client.PrivilegeShow(&ipa.PrivilegeShowArgs{Cn: data.Privilege.ValueString()}, &ipa.PrivilegeShowOptionalArgs{All: &all})
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading privilege %q: %s", data.Privilege.ValueString(), err))
		return
	}
	if !stringSliceContainsFold(res.Result.MemberofPermission, data.Permission.ValueString()) {
		resp.State.RemoveResource(ctx)
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.Privilege.ValueString(), data.Permission.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PrivilegePermissionMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *PrivilegePermissionMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PrivilegePermissionMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	permissions := []string{data.Permission.ValueString()}
	_, err := r.client.PrivilegeRemovePermission(&ipa.PrivilegeRemovePermissionArgs{Cn: data.Privilege.ValueString()}, &ipa.PrivilegeRemovePermissionOptionalArgs{Permission: &permissions})
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing permission %q from privilege %q: %s", data.Permission.ValueString(), data.Privilege.ValueString(), err))
	}
}

func (r *PrivilegePermissionMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parent, member, err := parsePolicyMembershipID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), policyMembershipID(parent, member))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("privilege"), parent)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("permission"), member)...)
}

// ---- Role privilege membership ----

var _ resource.Resource = &RolePrivilegeMembershipResource{}
var _ resource.ResourceWithImportState = &RolePrivilegeMembershipResource{}

func NewRolePrivilegeMembershipResource() resource.Resource {
	return &RolePrivilegeMembershipResource{}
}

type RolePrivilegeMembershipResource struct{ client *ipa.Client }

type RolePrivilegeMembershipResourceModel struct {
	ID        types.String `tfsdk:"id"`
	Role      types.String `tfsdk:"role"`
	Privilege types.String `tfsdk:"privilege"`
}

func (r *RolePrivilegeMembershipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_privilege_membership"
}

func (r *RolePrivilegeMembershipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Membership of one privilege in one FreeIPA role.",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"role":      schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"privilege": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *RolePrivilegeMembershipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *RolePrivilegeMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RolePrivilegeMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	privileges := []string{data.Privilege.ValueString()}
	_, err := r.client.RoleAddPrivilege(&ipa.RoleAddPrivilegeArgs{Cn: data.Role.ValueString()}, &ipa.RoleAddPrivilegeOptionalArgs{Privilege: &privileges})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding privilege %q to role %q: %s", data.Privilege.ValueString(), data.Role.ValueString(), err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.Role.ValueString(), data.Privilege.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RolePrivilegeMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RolePrivilegeMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	all := true
	res, err := r.client.RoleShow(&ipa.RoleShowArgs{Cn: data.Role.ValueString()}, &ipa.RoleShowOptionalArgs{All: &all})
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading role %q: %s", data.Role.ValueString(), err))
		return
	}
	if !stringSliceContainsFold(res.Result.MemberofPrivilege, data.Privilege.ValueString()) {
		resp.State.RemoveResource(ctx)
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.Role.ValueString(), data.Privilege.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RolePrivilegeMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *RolePrivilegeMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RolePrivilegeMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	privileges := []string{data.Privilege.ValueString()}
	_, err := r.client.RoleRemovePrivilege(&ipa.RoleRemovePrivilegeArgs{Cn: data.Role.ValueString()}, &ipa.RoleRemovePrivilegeOptionalArgs{Privilege: &privileges})
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing privilege %q from role %q: %s", data.Privilege.ValueString(), data.Role.ValueString(), err))
	}
}

func (r *RolePrivilegeMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parent, member, err := parsePolicyMembershipID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), policyMembershipID(parent, member))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), parent)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("privilege"), member)...)
}

// ---- Role host membership ----

var _ resource.Resource = &RoleHostMembershipResource{}
var _ resource.ResourceWithImportState = &RoleHostMembershipResource{}

func NewRoleHostMembershipResource() resource.Resource { return &RoleHostMembershipResource{} }

type RoleHostMembershipResource struct{ client *ipa.Client }

type RoleHostMembershipResourceModel struct {
	ID   types.String `tfsdk:"id"`
	Role types.String `tfsdk:"role"`
	Host types.String `tfsdk:"host"`
}

func (r *RoleHostMembershipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_host_membership"
}

func (r *RoleHostMembershipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Membership of one host in one FreeIPA role.",
		Attributes: map[string]schema.Attribute{
			"id":   schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"role": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"host": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *RoleHostMembershipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *RoleHostMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RoleHostMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hosts := []string{data.Host.ValueString()}
	_, err := r.client.RoleAddMember(&ipa.RoleAddMemberArgs{Cn: data.Role.ValueString()}, &ipa.RoleAddMemberOptionalArgs{Host: &hosts})
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding host %q to role %q: %s", data.Host.ValueString(), data.Role.ValueString(), err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.Role.ValueString(), data.Host.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RoleHostMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RoleHostMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	all := true
	res, err := r.client.RoleShow(&ipa.RoleShowArgs{Cn: data.Role.ValueString()}, &ipa.RoleShowOptionalArgs{All: &all})
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading role %q: %s", data.Role.ValueString(), err))
		return
	}
	if !stringSliceContainsFold(res.Result.MemberHost, data.Host.ValueString()) {
		resp.State.RemoveResource(ctx)
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.Role.ValueString(), data.Host.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RoleHostMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *RoleHostMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RoleHostMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hosts := []string{data.Host.ValueString()}
	_, err := r.client.RoleRemoveMember(&ipa.RoleRemoveMemberArgs{Cn: data.Role.ValueString()}, &ipa.RoleRemoveMemberOptionalArgs{Host: &hosts})
	if err != nil && !strings.Contains(err.Error(), "NotFound") {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing host %q from role %q: %s", data.Host.ValueString(), data.Role.ValueString(), err))
	}
}

func (r *RoleHostMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parent, member, err := parsePolicyMembershipID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), policyMembershipID(parent, member))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), parent)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host"), member)...)
}
