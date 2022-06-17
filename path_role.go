package vault_k8s_secrets_engine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type kubernetesRoleEntry struct {
	Name      string        `json:"name"`
	Namespace string        `json:"namespace"`
	Rules     string        `json:"rules"`
	Bindings  []string      `json:"bindings"`
	TTL       time.Duration `json:"ttl"`
	MaxTTL    time.Duration `json:"max_ttl"`
}

// toResponseData returns response data for a role
func (r *kubernetesRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		keyName:      r.Name,
		keyNamespace: r.Namespace,
		keyRules:     r.Rules,
		keyBindings:  r.Bindings,
		keyTTL:       r.TTL.Seconds(),
		keyMaxTTL:    r.MaxTTL.Seconds(),
	}
	return respData
}

// pathRole extends the Vault API with a `/role`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. You can also define different
// path patterns to list all roles.
func pathRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: rolePath + "/" + framework.GenericNameRegex(keyName),
			Fields: map[string]*framework.FieldSchema{
				keyName: {
					Type:        framework.TypeNameString,
					Description: "Name of the role",
					Required:    true,
				},
				keyNamespace: {
					Type:        framework.TypeString,
					Description: "Namespace of the role ServiceAccount",
					Default:     "kube-system",
					Required:    true,
				},
				keyRules: {
					Type:        framework.TypeString,
					Description: "Rules of the role",
					Required:    true,
				},
				keyBindings: {
					Type:        framework.TypeStringSlice,
					Description: "Namespace bindings of the role. If not set rules will be global.",
					Required:    false,
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
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: rolePath + "/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

// pathRolesList makes a request to Vault storage to retrieve a list of roles for the backend
func (b *backend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, rolePath+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathRolesRead makes a request to Vault storage to read a role and return response data
func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get(keyName).(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

// pathRolesWrite makes a request to Vault storage to update a role based on the attributes passed to the role configuration
func (b *backend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk(keyName)
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &kubernetesRoleEntry{}
	}

	createOperation := req.Operation == logical.CreateOperation

	if name, ok := d.GetOk(keyName); ok {
		roleEntry.Name = name.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing name in role")
	}

	namespace := d.Get(keyNamespace).(string)
	if namespace != "" {
		roleEntry.Namespace = namespace
	} else if createOperation {
		return nil, fmt.Errorf("missing namespace in role")
	}

	if rules, ok := d.GetOk(keyRules); ok {
		roleEntry.Rules = rules.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing rules in role")
	}

	if ttlRaw, ok := d.GetOk(keyTTL); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.TTL = time.Duration(d.Get(keyTTL).(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk(keyMaxTTL); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if createOperation {
		roleEntry.MaxTTL = time.Duration(d.Get(keyMaxTTL).(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRolesDelete makes a request to Vault storage to delete a role
func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, rolePath+"/"+d.Get(keyName).(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}

	return nil, nil
}

// setRole adds the role to the Vault storage API
func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *kubernetesRoleEntry) error {
	entry, err := logical.StorageEntryJSON(rolePath+"/"+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// getRole gets the role from the Vault storage API
func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*kubernetesRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, rolePath+"/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role kubernetesRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating kubernetes credentials.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate kubernetes RBAC objects.
You can configure a role to manage a service account by setting the roles ans the namespace.
`
	pathRoleListHelpSynopsis    = `List the existing roles in Kubernetes backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)
