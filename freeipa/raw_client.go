// SPDX-License-Identifier: GPL-3.0-only

package freeipa

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"

	ipa "github.com/infra-monkey/go-freeipa/freeipa"
	k5client "github.com/jcmturner/gokrb5/v8/client"
	k5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

const rawFreeIPAAPIVersion = "2.257"

type rawFreeIPAClient struct {
	host     string
	hc       *http.Client
	user     string
	password string
	k5client *k5client.Client
}

type rawFreeIPAClientRegistration struct {
	once   sync.Once
	config freeipaProviderModel
	client *rawFreeIPAClient
	err    error
}

var rawFreeIPAClients sync.Map // map[*ipa.Client]*rawFreeIPAClientRegistration

func registerRawFreeIPAClientConfig(client *ipa.Client, config *freeipaProviderModel) {
	if client == nil || config == nil {
		return
	}
	registration := &rawFreeIPAClientRegistration{config: *config}
	rawFreeIPAClients.Store(client, registration)
}

func rawFreeIPAClientFor(client *ipa.Client) (*rawFreeIPAClient, error) {
	value, ok := rawFreeIPAClients.Load(client)
	if !ok {
		return nil, fmt.Errorf("FreeIPA compatibility JSON-RPC client is unavailable")
	}
	registration, ok := value.(*rawFreeIPAClientRegistration)
	if !ok {
		return nil, fmt.Errorf("unexpected FreeIPA compatibility client registration type %T", value)
	}
	registration.once.Do(func() {
		registration.client, registration.err = newRawFreeIPAClient(&registration.config)
	})
	return registration.client, registration.err
}

func newRawFreeIPAClient(conf *freeipaProviderModel) (*rawFreeIPAClient, error) {
	var roots *x509.CertPool
	if conf.CaCertificate.ValueString() != "" {
		pem, err := os.ReadFile(conf.CaCertificate.ValueString())
		if err != nil {
			return nil, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("failed to load FreeIPA CA certificate %s", conf.CaCertificate.ValueString())
		}
	}
	baseTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: conf.InsecureSkipVerify.ValueBool(),
			RootCAs:            roots,
		},
	}
	var transport http.RoundTripper = baseTransport
	if kerberosConfigured(conf) {
		transport = &kerberosLoginRetryTransport{base: baseTransport}
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	raw := &rawFreeIPAClient{
		host:     conf.Host.ValueString(),
		hc:       &http.Client{Transport: transport, Jar: jar},
		user:     conf.Username.ValueString(),
		password: conf.Password.ValueString(),
	}

	if kerberosConfigured(conf) {
		principal, realm, err := normalizeKerberosPrincipal(conf.KerberosPrincipal.ValueString(), conf.KerberosRealm.ValueString())
		if err != nil {
			return nil, err
		}
		krb5Reader, err := os.Open(conf.Krb5ConfPath.ValueString())
		if err != nil {
			return nil, fmt.Errorf("open krb5.conf: %w", err)
		}
		defer krb5Reader.Close()
		cfg, err := k5config.NewFromReader(krb5Reader)
		if err != nil {
			return nil, fmt.Errorf("read krb5.conf: %w", err)
		}
		keytabReader, err := os.Open(conf.KeytabPath.ValueString())
		if err != nil {
			return nil, fmt.Errorf("open Kerberos keytab: %w", err)
		}
		defer keytabReader.Close()
		keytabBytes, err := io.ReadAll(keytabReader)
		if err != nil {
			return nil, fmt.Errorf("read Kerberos keytab: %w", err)
		}
		kt := keytab.New()
		if err := kt.Unmarshal(keytabBytes); err != nil {
			return nil, fmt.Errorf("parse Kerberos keytab: %w", err)
		}
		raw.k5client = k5client.NewWithKeytab(principal, realm, kt, cfg)
		raw.user = ""
		raw.password = ""
	}

	return raw, nil
}

func (c *rawFreeIPAClient) login() error {
	if c.k5client != nil {
		endpoint := fmt.Sprintf("https://%s/ipa/session/login_kerberos", c.host)
		client := spnego.NewClient(c.k5client, c.hc, "")
		req, err := http.NewRequest(http.MethodPost, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.host))
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("FreeIPA Kerberos login returned HTTP %d", resp.StatusCode)
		}
		return nil
	}

	form := url.Values{"user": {c.user}, "password": {c.password}}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/ipa/session/login_password", c.host), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.host))
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("FreeIPA password login returned HTTP %d", resp.StatusCode)
	}
	return nil
}

type rawFreeIPAResponse struct {
	Error  *ipa.Error      `json:"error"`
	Result json.RawMessage `json:"result"`
}

func (c *rawFreeIPAClient) call(method string, kwargs map[string]any, out any) error {
	if kwargs == nil {
		kwargs = map[string]any{}
	}
	kwargs["version"] = rawFreeIPAAPIVersion
	payload := map[string]any{
		"method": method,
		"params": []any{[]any{}, kwargs},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	do := func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/ipa/session/json", c.host), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa/ui", c.host))
		return c.hc.Do(req)
	}

	resp, err := do()
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if err := c.login(); err != nil {
			return err
		}
		resp, err = do()
		if err != nil {
			return err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("FreeIPA JSON-RPC returned HTTP %d", resp.StatusCode)
	}

	var envelope rawFreeIPAResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, out)
}

type rawPermission struct {
	Name               string
	Description        string
	Rights             []string
	IncludedAttributes []string
	Target             string
	ObjectType         string
	MemberOf           []string
}

func rawString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []any:
		if len(v) == 1 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

func rawStrings(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (c *rawFreeIPAClient) permissionShow(name string) (*rawPermission, error) {
	var result struct {
		Result map[string]any `json:"result"`
	}
	// type and memberof are FreeIPA virtual attributes reconstructed from
	// ipapermlocation/ipapermtargetfilter only in non-raw permission_show output.
	// Request all attributes but keep server-side post-processing enabled so
	// Terraform can round-trip convenience targeting without perpetual drift.
	if err := c.call("permission_show", map[string]any{"cn": name, "all": true, "raw": false}, &result); err != nil {
		return nil, err
	}
	record := result.Result
	attrs := rawStrings(record["ipapermincludedattr"])
	if len(attrs) == 0 {
		attrs = rawStrings(record["attrs"])
	}
	return &rawPermission{
		Name:               rawString(record["cn"]),
		Description:        rawString(record["description"]),
		Rights:             rawStrings(record["ipapermright"]),
		IncludedAttributes: attrs,
		Target:             rawString(record["ipapermtarget"]),
		ObjectType:         rawString(record["type"]),
		MemberOf:           rawStrings(record["memberof"]),
	}, nil
}

func permissionKwargs(permission rawPermission) map[string]any {
	kwargs := map[string]any{
		"cn":           permission.Name,
		"ipapermright": permission.Rights,
		"attrs":        permission.IncludedAttributes,
	}
	if permission.Target != "" {
		kwargs["ipapermtarget"] = permission.Target
	}
	if permission.ObjectType != "" {
		kwargs["type"] = permission.ObjectType
	}
	if len(permission.MemberOf) != 0 {
		kwargs["memberof"] = permission.MemberOf
	}
	if permission.Description != "" {
		kwargs["setattr"] = []string{"description=" + permission.Description}
	}
	return kwargs
}

func (c *rawFreeIPAClient) permissionAdd(permission rawPermission) error {
	return c.call("permission_add", permissionKwargs(permission), nil)
}

func (c *rawFreeIPAClient) permissionMod(permission rawPermission) error {
	return c.call("permission_mod", permissionKwargs(permission), nil)
}

func (c *rawFreeIPAClient) permissionDel(name string) error {
	return c.call("permission_del", map[string]any{"cn": []string{name}}, nil)
}

type rawCertprofile struct {
	Name        string
	Description string
	StoreIssued bool
	Config      string
}

func rawBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	case []any:
		if len(v) == 1 {
			return rawBool(v[0])
		}
	}
	return false
}

func rawBinaryString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case map[string]any:
		encoded, ok := v["__base64__"].(string)
		if !ok {
			return "", fmt.Errorf("unexpected FreeIPA binary wrapper: %#v", v)
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("decode FreeIPA base64 value: %w", err)
		}
		return string(data), nil
	default:
		return "", fmt.Errorf("unexpected FreeIPA binary value type %T", value)
	}
}

func (c *rawFreeIPAClient) certprofileShow(name string) (*rawCertprofile, error) {
	var result map[string]any
	if err := c.call("certprofile_show", map[string]any{
		"cn":  name,
		"all": true,
		"raw": true,
		"out": "-",
	}, &result); err != nil {
		return nil, err
	}
	record, ok := result["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected certprofile_show result type %T", result["result"])
	}
	config, err := rawBinaryString(record["config"])
	if err != nil {
		return nil, err
	}
	return &rawCertprofile{
		Name:        rawString(record["cn"]),
		Description: rawString(record["description"]),
		StoreIssued: rawBool(record["ipacertprofilestoreissued"]),
		Config:      config,
	}, nil
}

func (c *rawFreeIPAClient) certprofileImport(profile rawCertprofile) error {
	return c.call("certprofile_import", map[string]any{
		"cn":                        profile.Name,
		"description":               profile.Description,
		"file":                      profile.Config,
		"ipacertprofilestoreissued": profile.StoreIssued,
	}, nil)
}

func (c *rawFreeIPAClient) certprofileMod(profile rawCertprofile) error {
	return c.call("certprofile_mod", map[string]any{
		"cn":                        profile.Name,
		"description":               profile.Description,
		"file":                      profile.Config,
		"ipacertprofilestoreissued": profile.StoreIssued,
	}, nil)
}

func (c *rawFreeIPAClient) certprofileDel(name string) error {
	return c.call("certprofile_del", map[string]any{"cn": []string{name}}, nil)
}

type rawService struct {
	DN                   string
	AllowedRetrieveHosts []string
	AllowedCreateHosts   []string
}

func (c *rawFreeIPAClient) serviceShow(principal string) (*rawService, error) {
	var result map[string]any
	if err := c.call("service_show", map[string]any{
		"krbcanonicalname": principal,
		"all":              true,
		"raw":              true,
	}, &result); err != nil {
		return nil, err
	}
	record, ok := result["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected service_show result type %T", result["result"])
	}
	dn := rawString(record["dn"])
	if dn == "" {
		return nil, fmt.Errorf("FreeIPA service %q did not return dn metadata", principal)
	}
	return &rawService{
		DN:                   dn,
		AllowedRetrieveHosts: rawStrings(record["ipaallowedtoperform_read_keys_host"]),
		AllowedCreateHosts:   rawStrings(record["ipaallowedtoperform_write_keys_host"]),
	}, nil
}

func (c *rawFreeIPAClient) serviceKeytabAccessShow(principal string) (*rawService, error) {
	var result map[string]any
	if err := c.call("service_show", map[string]any{
		"krbcanonicalname": principal,
		"all":              true,
	}, &result); err != nil {
		return nil, err
	}
	record, ok := result["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected service_show result type %T", result["result"])
	}
	return &rawService{
		DN:                   rawString(record["dn"]),
		AllowedRetrieveHosts: rawStrings(record["ipaallowedtoperform_read_keys_host"]),
		AllowedCreateHosts:   rawStrings(record["ipaallowedtoperform_write_keys_host"]),
	}, nil
}

type rawCAACL struct {
	Name            string
	Description     string
	Enabled         bool
	CACategory      string
	ProfileCategory string
	UserCategory    string
	HostCategory    string
	ServiceCategory string
	Profiles        []string
	Services        []string
}

func (c *rawFreeIPAClient) caACLShow(name string) (*rawCAACL, error) {
	var result map[string]any
	if err := c.call("caacl_show", map[string]any{
		"cn":  name,
		"all": true,
	}, &result); err != nil {
		return nil, err
	}
	record, ok := result["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected caacl_show result type %T", result["result"])
	}
	return &rawCAACL{
		Name:            rawString(record["cn"]),
		Description:     rawString(record["description"]),
		Enabled:         rawBool(record["ipaenabledflag"]),
		CACategory:      rawString(record["ipacacategory"]),
		ProfileCategory: rawString(record["ipacertprofilecategory"]),
		UserCategory:    rawString(record["usercategory"]),
		HostCategory:    rawString(record["hostcategory"]),
		ServiceCategory: rawString(record["servicecategory"]),
		Profiles:        rawStrings(record["ipamembercertprofile_certprofile"]),
		Services:        rawStrings(record["memberservice_service"]),
	}, nil
}

func caACLKwargs(acl rawCAACL) map[string]any {
	kwargs := map[string]any{
		"cn":             acl.Name,
		"ipaenabledflag": acl.Enabled,
	}
	if acl.Description != "" {
		kwargs["description"] = acl.Description
	}
	if acl.CACategory != "" {
		kwargs["ipacacategory"] = acl.CACategory
	}
	if acl.ProfileCategory != "" {
		kwargs["ipacertprofilecategory"] = acl.ProfileCategory
	}
	if acl.UserCategory != "" {
		kwargs["usercategory"] = acl.UserCategory
	}
	if acl.HostCategory != "" {
		kwargs["hostcategory"] = acl.HostCategory
	}
	if acl.ServiceCategory != "" {
		kwargs["servicecategory"] = acl.ServiceCategory
	}
	return kwargs
}

func (c *rawFreeIPAClient) caACLAdd(acl rawCAACL) error {
	return c.call("caacl_add", caACLKwargs(acl), nil)
}

func (c *rawFreeIPAClient) caACLMod(name string, changes map[string]any) error {
	kwargs := make(map[string]any, len(changes)+1)
	for key, value := range changes {
		kwargs[key] = value
	}
	kwargs["cn"] = name
	return c.call("caacl_mod", kwargs, nil)
}

func (c *rawFreeIPAClient) caACLDel(name string) error {
	return c.call("caacl_del", map[string]any{"cn": []string{name}}, nil)
}

func (c *rawFreeIPAClient) caACLAddProfile(name, profile string) error {
	return c.call("caacl_add_profile", map[string]any{"cn": name, "certprofile": []string{profile}}, nil)
}

func (c *rawFreeIPAClient) caACLRemoveProfile(name, profile string) error {
	return c.call("caacl_remove_profile", map[string]any{"cn": name, "certprofile": []string{profile}}, nil)
}

func (c *rawFreeIPAClient) caACLAddService(name, service string) error {
	return c.call("caacl_add_service", map[string]any{"cn": name, "service": []string{service}}, nil)
}

func (c *rawFreeIPAClient) caACLRemoveService(name, service string) error {
	return c.call("caacl_remove_service", map[string]any{"cn": name, "service": []string{service}}, nil)
}
