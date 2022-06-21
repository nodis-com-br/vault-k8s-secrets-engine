package secretsengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

func pathCredentials(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: credsPath + framework.GenericNameRegex(keyVaultCredsName),
		Fields: map[string]*framework.FieldSchema{
			keyVaultCredsName: {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
			keyCredsTTL: {
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

	role, err := getRole(ctx, req.Storage, rolePath+d.Get(keyVaultCredsName).(string))
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	} else if role == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	if credentialsTTL, ok := d.GetOk(keyCredsTTL); ok {
		role.TTL = time.Duration(credentialsTTL.(int)) * time.Second
	}

	s, err := b.createSecret(ctx, req, role)
	if err != nil {
		return nil, err
	}

	encodedServiceAccount, _ := json.Marshal(s.ServiceAccount)

	resp := b.Secret(secretType).Response(map[string]interface{}{
		keySecretToken:  s.ServiceAccount.Secret.Token,
		keySecretHost:   s.Host,
		keySecretCACert: s.ServiceAccount.Secret.CACert,
		keyKubeConfig:   s.KubeConfig,
	}, map[string]interface{}{
		keyEncodedServiceAccount:      string(encodedServiceAccount),
		keyEncodedClusterRoles:        s.EncodedClusterRoles,
		keyEncodedRoleBindings:        s.EncodedRoleBindings,
		keyEncodedClusterRoleBindings: s.EncodedClusterRoleBindings,
	})

	// set up TTL for secret so it gets automatically revoked
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	resp.Secret.Renewable = false

	return resp, nil

}
