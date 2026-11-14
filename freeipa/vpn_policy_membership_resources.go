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

type policyMembershipMutation func() (int, ipa.FailedOperations, error)
type policyMembershipVerify func() (bool, error)

func createPolicyMembership(parentKind, parent, memberKind, member string, mutate policyMembershipMutation, verify policyMembershipVerify) error {
	completed, failed, err := mutate()
	if err != nil {
		return err
	}
	failures := failed.GetFailures()
	if completed != 1 || len(failures) != 0 {
		return fmt.Errorf(
			"FreeIPA did not add %s %q to %s %q: completed %d membership changes with failures %v",
			memberKind,
			member,
			parentKind,
			parent,
			completed,
			failures,
		)
	}
	present, err := verify()
	if err != nil {
		return fmt.Errorf("verify %s %q membership in %s %q: %w", memberKind, member, parentKind, parent, err)
	}
	if !present {
		return fmt.Errorf(
			"FreeIPA reported %s %q added to %s %q but the membership is absent on read-back",
			memberKind,
			member,
			parentKind,
			parent,
		)
	}
	return nil
}

func deletePolicyMembership(parentKind, parent, memberKind, member string, mutate func() error, verify policyMembershipVerify) error {
	if err := mutate(); err != nil && !strings.Contains(err.Error(), "NotFound") {
		return err
	}
	present, err := verify()
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			return nil
		}
		return fmt.Errorf("verify removal of %s %q from %s %q: %w", memberKind, member, parentKind, parent, err)
	}
	if present {
		return fmt.Errorf("%s %q is still a member of %s %q after removal", memberKind, member, parentKind, parent)
	}
	return nil
}

func privilegePermissionMembershipPresent(client *ipa.Client, privilege, permission string) (bool, error) {
	all := true
	res, err := client.PrivilegeShow(&ipa.PrivilegeShowArgs{Cn: privilege}, &ipa.PrivilegeShowOptionalArgs{All: &all})
	if err != nil {
		return false, err
	}
	return stringSliceContainsFold(res.Result.MemberofPermission, permission), nil
}

func rolePrivilegeMembershipPresent(client *ipa.Client, role, privilege string) (bool, error) {
	all := true
	res, err := client.RoleShow(&ipa.RoleShowArgs{Cn: role}, &ipa.RoleShowOptionalArgs{All: &all})
	if err != nil {
		return false, err
	}
	return stringSliceContainsFold(res.Result.MemberofPrivilege, privilege), nil
}

func roleHostMembershipPresent(client *ipa.Client, role, host string) (bool, error) {
	all := true
	res, err := client.RoleShow(&ipa.RoleShowArgs{Cn: role}, &ipa.RoleShowOptionalArgs{All: &all})
	if err != nil {
		return false, err
	}
	return stringSliceContainsFold(res.Result.MemberHost, host), nil
}

func roleServiceMembershipPresent(client *ipa.Client, role, service string) (bool, error) {
	all := true
	res, err := client.RoleShow(&ipa.RoleShowArgs{Cn: role}, &ipa.RoleShowOptionalArgs{All: &all})
	if err != nil {
		return false, err
	}
	if res.Result.MemberService == nil {
		return false, nil
	}
	return stringSliceContainsServicePrincipal(*res.Result.MemberService, service), nil
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
	privilege := data.Privilege.ValueString()
	permission := data.Permission.ValueString()
	err := createPolicyMembership(
		"privilege",
		privilege,
		"permission",
		permission,
		func() (int, ipa.FailedOperations, error) {
			permissions := []string{permission}
			result, err := r.client.PrivilegeAddPermission(
				&ipa.PrivilegeAddPermissionArgs{Cn: privilege},
				&ipa.PrivilegeAddPermissionOptionalArgs{Permission: &permissions},
			)
			if err != nil {
				return 0, nil, err
			}
			if result == nil {
				return 0, nil, fmt.Errorf("FreeIPA returned an empty privilege_add_permission result")
			}
			return result.Completed, result.Failed, nil
		},
		func() (bool, error) {
			return privilegePermissionMembershipPresent(r.client, privilege, permission)
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding permission %q to privilege %q: %s", permission, privilege, err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(privilege, permission))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PrivilegePermissionMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PrivilegePermissionMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	present, err := privilegePermissionMembershipPresent(r.client, data.Privilege.ValueString(), data.Permission.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading privilege %q: %s", data.Privilege.ValueString(), err))
		return
	}
	if !present {
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
	privilege := data.Privilege.ValueString()
	permission := data.Permission.ValueString()
	err := deletePolicyMembership(
		"privilege",
		privilege,
		"permission",
		permission,
		func() error {
			permissions := []string{permission}
			_, err := r.client.PrivilegeRemovePermission(
				&ipa.PrivilegeRemovePermissionArgs{Cn: privilege},
				&ipa.PrivilegeRemovePermissionOptionalArgs{Permission: &permissions},
			)
			return err
		},
		func() (bool, error) {
			return privilegePermissionMembershipPresent(r.client, privilege, permission)
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing permission %q from privilege %q: %s", permission, privilege, err))
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
	role := data.Role.ValueString()
	privilege := data.Privilege.ValueString()
	err := createPolicyMembership(
		"role",
		role,
		"privilege",
		privilege,
		func() (int, ipa.FailedOperations, error) {
			privileges := []string{privilege}
			result, err := r.client.RoleAddPrivilege(
				&ipa.RoleAddPrivilegeArgs{Cn: role},
				&ipa.RoleAddPrivilegeOptionalArgs{Privilege: &privileges},
			)
			if err != nil {
				return 0, nil, err
			}
			if result == nil {
				return 0, nil, fmt.Errorf("FreeIPA returned an empty role_add_privilege result")
			}
			return result.Completed, result.Failed, nil
		},
		func() (bool, error) {
			return rolePrivilegeMembershipPresent(r.client, role, privilege)
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding privilege %q to role %q: %s", privilege, role, err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(role, privilege))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RolePrivilegeMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RolePrivilegeMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	present, err := rolePrivilegeMembershipPresent(r.client, data.Role.ValueString(), data.Privilege.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading role %q: %s", data.Role.ValueString(), err))
		return
	}
	if !present {
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
	role := data.Role.ValueString()
	privilege := data.Privilege.ValueString()
	err := deletePolicyMembership(
		"role",
		role,
		"privilege",
		privilege,
		func() error {
			privileges := []string{privilege}
			_, err := r.client.RoleRemovePrivilege(
				&ipa.RoleRemovePrivilegeArgs{Cn: role},
				&ipa.RoleRemovePrivilegeOptionalArgs{Privilege: &privileges},
			)
			return err
		},
		func() (bool, error) {
			return rolePrivilegeMembershipPresent(r.client, role, privilege)
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing privilege %q from role %q: %s", privilege, role, err))
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
	role := data.Role.ValueString()
	host := data.Host.ValueString()
	err := createPolicyMembership(
		"role",
		role,
		"host",
		host,
		func() (int, ipa.FailedOperations, error) {
			hosts := []string{host}
			result, err := r.client.RoleAddMember(
				&ipa.RoleAddMemberArgs{Cn: role},
				&ipa.RoleAddMemberOptionalArgs{Host: &hosts},
			)
			if err != nil {
				return 0, nil, err
			}
			if result == nil {
				return 0, nil, fmt.Errorf("FreeIPA returned an empty role_add_member result")
			}
			return result.Completed, result.Failed, nil
		},
		func() (bool, error) {
			return roleHostMembershipPresent(r.client, role, host)
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding host %q to role %q: %s", host, role, err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(role, host))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RoleHostMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RoleHostMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	present, err := roleHostMembershipPresent(r.client, data.Role.ValueString(), data.Host.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading role %q: %s", data.Role.ValueString(), err))
		return
	}
	if !present {
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
	role := data.Role.ValueString()
	host := data.Host.ValueString()
	err := deletePolicyMembership(
		"role",
		role,
		"host",
		host,
		func() error {
			hosts := []string{host}
			_, err := r.client.RoleRemoveMember(
				&ipa.RoleRemoveMemberArgs{Cn: role},
				&ipa.RoleRemoveMemberOptionalArgs{Host: &hosts},
			)
			return err
		},
		func() (bool, error) {
			return roleHostMembershipPresent(r.client, role, host)
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing host %q from role %q: %s", host, role, err))
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

// ---- Role service membership ----

var _ resource.Resource = &RoleServiceMembershipResource{}
var _ resource.ResourceWithImportState = &RoleServiceMembershipResource{}

func NewRoleServiceMembershipResource() resource.Resource { return &RoleServiceMembershipResource{} }

type RoleServiceMembershipResource struct{ client *ipa.Client }

type RoleServiceMembershipResourceModel struct {
	ID      types.String `tfsdk:"id"`
	Role    types.String `tfsdk:"role"`
	Service types.String `tfsdk:"service"`
}

func (r *RoleServiceMembershipResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_service_membership"
}

func (r *RoleServiceMembershipResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Membership of one service principal in one FreeIPA role.",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"role":    schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"service": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *RoleServiceMembershipResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *RoleServiceMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RoleServiceMembershipResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	role := data.Role.ValueString()
	service := data.Service.ValueString()
	err := createPolicyMembership(
		"role",
		role,
		"service",
		service,
		func() (int, ipa.FailedOperations, error) {
			services := []string{service}
			result, err := r.client.RoleAddMember(
				&ipa.RoleAddMemberArgs{Cn: role},
				&ipa.RoleAddMemberOptionalArgs{Service: &services},
			)
			if err != nil {
				return 0, nil, err
			}
			if result == nil {
				return 0, nil, fmt.Errorf("FreeIPA returned an empty role_add_member result")
			}
			return result.Completed, result.Failed, nil
		},
		func() (bool, error) {
			return roleServiceMembershipPresent(r.client, role, service)
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error adding service %q to role %q: %s", service, role, err))
		return
	}
	data.ID = types.StringValue(policyMembershipID(role, service))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RoleServiceMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RoleServiceMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	present, err := roleServiceMembershipPresent(r.client, data.Role.ValueString(), data.Service.ValueString())
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error reading role %q: %s", data.Role.ValueString(), err))
		return
	}
	if !present {
		resp.State.RemoveResource(ctx)
		return
	}
	data.ID = types.StringValue(policyMembershipID(data.Role.ValueString(), data.Service.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *RoleServiceMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *RoleServiceMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RoleServiceMembershipResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	role := data.Role.ValueString()
	service := data.Service.ValueString()
	err := deletePolicyMembership(
		"role",
		role,
		"service",
		service,
		func() error {
			services := []string{service}
			_, err := r.client.RoleRemoveMember(
				&ipa.RoleRemoveMemberArgs{Cn: role},
				&ipa.RoleRemoveMemberOptionalArgs{Service: &services},
			)
			return err
		},
		func() (bool, error) {
			return roleServiceMembershipPresent(r.client, role, service)
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Error removing service %q from role %q: %s", service, role, err))
	}
}

func (r *RoleServiceMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parent, member, err := parsePolicyMembershipID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Import Error", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), policyMembershipID(parent, member))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), parent)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service"), member)...)
}
