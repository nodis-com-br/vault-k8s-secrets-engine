package secretsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	rbac "k8s.io/api/rbac/v1"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type VaultRole struct {
	CredentialType          string        `json:"credential_type"`
	BindingRules            []BindingRule `json:"binding_rules"`
	ServiceAccountNamespace string        `json:"serviceaccount_namespace"`
	ListNamespaces          bool          `json:"list_namespaces"`
	ViewNodes               bool          `json:"view_nodes"`
	TTL                     time.Duration `json:"ttl"`
	MaxTTL                  time.Duration `json:"max_ttl"`
}

type BindingRule struct {
	Namespaces   []string          `json:"namespaces"`
	ClusterRoles []string          `json:"cluster_roles"`
	PolicyRules  []rbac.PolicyRule `json:"rules"`
}

// toResponseData returns response data for a role
func (r *VaultRole) toResponseData() map[string]interface{} {
	bindingRules, _ := json.Marshal(r.BindingRules)
	respData := map[string]interface{}{
		keyCredentialsType:  r.CredentialType,
		keyServiceAccountNs: r.ServiceAccountNamespace,
		keyBindingRules:     string(bindingRules),
		keyListNamespaces:   r.ListNamespaces,
		keyViewNodes:        r.ViewNodes,
		keyTTL:              r.TTL.Seconds(),
		keyMaxTTL:           r.MaxTTL.Seconds(),
	}
	return respData
}

func (r *VaultRole) Validate() error {

	if r.MaxTTL != 0 && r.TTL > r.MaxTTL {
		return fmt.Errorf("ttl cannot be greater than max_ttl")
	}

	if r.CredentialType == "certificate" {
		if (r.TTL > 0 && r.TTL < 600*time.Second) || (r.MaxTTL > 0 && r.MaxTTL < 600*time.Second) {
			return fmt.Errorf("certificate type credentials cannot specify a duration less than 600 seconds")
		}
	}

	if len(r.BindingRules) == 0 {
		return fmt.Errorf("binding rules list cannot be empty")
	}

	for i, _ := range r.BindingRules {
		if len(r.BindingRules[i].Namespaces) == 0 {
			return fmt.Errorf("namespace list cannot be empty")
		}
		if len(r.BindingRules[i].ClusterRoles) == 0 && len(r.BindingRules[i].PolicyRules) == 0 {
			return fmt.Errorf("cluster roles or policy rules must be provided")
		}
	}
	return nil

}

func pathRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: rolePath + framework.GenericNameRegex(keyVaultRoleName),
			Fields: map[string]*framework.FieldSchema{
				keyVaultRoleName: {
					Type:        framework.TypeNameString,
					Description: "Name of the role",
					Required:    true,
				},
				keyCredentialsType: {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("Type of credential create. Must be either 'certificate' or 'token'"),
					Default:     defaultCredentialsType,
				},
				keyBindingRules: {
					Type:        framework.TypeString,
					Description: "Binding rules of the role",
					Required:    true,
				},
				keyListNamespaces: {
					Type:        framework.TypeBool,
					Description: "Allow role to list namespaces.",
					Default:     defaultListNamespaces,
				},
				keyViewNodes: {
					Type:        framework.TypeBool,
					Description: "Allow role to view cluster nodes.",
					Default:     defaultViewNodes,
				},
				keyServiceAccountNs: {
					Type:        framework.TypeString,
					Description: "Namespace of the role ServiceAccount",
				},
				keyTTL: {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				keyMaxTTL: {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: rolePath + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

// pathRoleList makes a request to Vault storage to retrieve a list of validRoles for the backend
func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

// pathRoleRead makes a request to Vault storage to read a role and return response data
func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := getRole(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("path not found: %s", req.Path)
	}
	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

// pathRoleWrite makes a request to Vault storage to update a role based on the attributes passed to the role configuration
func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	role, err := getRole(ctx, req.Storage, req.Path)
	if err != nil {
		return nil, err
	} else if role == nil {
		role = &VaultRole{}
	}

	role.CredentialType = d.Get(keyCredentialsType).(string)

	if rules, ok := d.GetOk(keyBindingRules); ok {
		if err = json.Unmarshal([]byte(rules.(string)), &role.BindingRules); err != nil {
			return nil, err
		}
	}

	if listNamespaces, ok := d.GetOk(keyListNamespaces); ok {
		role.ListNamespaces = listNamespaces.(bool)
	}

	if viewNodes, ok := d.GetOk(keyViewNodes); ok {
		role.ViewNodes = viewNodes.(bool)
	}

	role.ServiceAccountNamespace = d.Get(keyServiceAccountNs).(string)

	if ttlRaw, ok := d.GetOk(keyTTL); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk(keyMaxTTL); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if err = setRole(ctx, req.Storage, req.Path, role); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleDelete makes a request to Vault storage to delete a role
func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}
	return nil, nil
}

// setRole adds the role to the Vault storage API
func setRole(ctx context.Context, s logical.Storage, path string, role *VaultRole) error {
	err := role.Validate()
	if err != nil {
		return fmt.Errorf("invalid role: %s", err)
	}
	entry, _ := logical.StorageEntryJSON(path, role)
	if err = s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

// getRole gets the role from the Vault storage API
func getRole(ctx context.Context, s logical.Storage, path string) (*VaultRole, error) {
	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var role VaultRole
	_ = entry.DecodeJSON(&role)
	return &role, nil
}
