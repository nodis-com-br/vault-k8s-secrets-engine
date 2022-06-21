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

type Role struct {
	ServiceAccountNamespace string        `json:"serviceaccount_namespace"`
	ListNamespaces          bool          `json:"list_namespaces"`
	ViewNodes               bool          `json:"view_nodes"`
	BindingRules            []BindingRule `json:"binding_rules"`
	TTL                     time.Duration `json:"ttl"`
	MaxTTL                  time.Duration `json:"max_ttl"`
}

type BindingRule struct {
	Namespaces   []string          `json:"namespaces"`
	ClusterRoles []string          `json:"cluster_roles"`
	Rules        []rbac.PolicyRule `json:"rules"`
}

// toResponseData returns response data for a role
func (r *Role) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		keyServiceAccountNamespace: r.ServiceAccountNamespace,
		keyBindingRules:            r.BindingRules,
		keyListNamespaces:          r.ListNamespaces,
		keyViewNodes:               r.ViewNodes,
		keyTTL:                     r.TTL.Seconds(),
		keyMaxTTL:                  r.MaxTTL.Seconds(),
	}
	return respData
}

func (r *Role) Validate() error {

	if r.MaxTTL != 0 && r.TTL > r.MaxTTL {
		return fmt.Errorf("ttl cannot be greater than max_ttl")
	}

	return nil

}

// pathRole extends the Vault API with a `/role`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. You can also define different
// path patterns to list all roles.
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
				keyBindingRules: {
					Type:        framework.TypeString,
					Description: "Binding rules of the role",
					Required:    true,
				},
				keyListNamespaces: {
					Type:        framework.TypeBool,
					Description: "Allow role to list namespaces.",
					Default:     false,
				},
				keyViewNodes: {
					Type:        framework.TypeBool,
					Description: "Allow role to view cluster nodes.",
					Default:     false,
				},
				keyServiceAccountNamespace: {
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

// pathRoleList makes a request to Vault storage to retrieve a list of roles for the backend
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
	} else if entry == nil {
		return nil, nil
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
		role = &Role{}
	}

	role.ServiceAccountNamespace = d.Get(keyServiceAccountNamespace).(string)

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

	if ttlRaw, ok := d.GetOk(keyTTL); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk(keyMaxTTL); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if err := setRole(ctx, req.Storage, req.Path, role); err != nil {
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
func setRole(ctx context.Context, s logical.Storage, path string, role *Role) error {

	err := role.Validate()
	if err != nil {
		return fmt.Errorf("invalid role: %s", err)
	}

	entry, err := logical.StorageEntryJSON(path, role)
	if err != nil {
		return err
	} else if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil

}

// getRole gets the role from the Vault storage API
func getRole(ctx context.Context, s logical.Storage, path string) (*Role, error) {

	entry, err := s.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role Role

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}
