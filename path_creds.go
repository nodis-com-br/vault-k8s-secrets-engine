package vault_k8s_secrets_engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: credsPath + "/" + framework.GenericNameRegex(keyName),
		Fields: map[string]*framework.FieldSchema{
			keyName: {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
			keyTTL: {
				Type:        framework.TypeDurationSecond,
				Description: "The time to live for the token in seconds. If not set or set to 0, will use system default.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
				Summary:  "Create new service account",
			},
		},
	}
}

func (b *backend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get(keyName).(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createCredentials(ctx, req, roleEntry)
}

func (b *backend) createCredentials(ctx context.Context, req *logical.Request, role *kubernetesRoleEntry) (*logical.Response, error) {

	resp, err := b.createSecret(ctx, req, role)
	if err != nil {
		return nil, err
	}

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}
