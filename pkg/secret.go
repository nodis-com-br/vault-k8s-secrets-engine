/*
 * Vault Kubernetes Secrets Engine
 *
 * This is a plugin for generating dynamic kubernetes credentials
 * for use with Hashicorp Vault
 *
 *
 * Contact: pedro.tonini@hotmail.com
 */

package secretsengine

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func secret(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretType,
		Fields: map[string]*framework.FieldSchema{
			keyServiceAccount: {
				Type:        framework.TypeString,
				Description: "Service account",
			},
			keyClusterRoles: {
				Type:        framework.TypeString,
				Description: "Cluster roles",
			},
			keyRoleBindings: {
				Type:        framework.TypeString,
				Description: "Role bindings",
			},
			keyClusterRoleBindings: {
				Type:        framework.TypeString,
				Description: "Cluster role bindings",
			},
		},
		Revoke: b.revokeSecret,
	}
}

// revokeSecret deletes all bindings, secrets and service accounts
//associated with the generated identity
func (b *backend) revokeSecret(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	var serviceAccount *corev1.ServiceAccount
	var clusterRoles []*rbacv1.ClusterRole
	var clusterRoleBindings []*rbacv1.ClusterRoleBinding
	var roleBindings []*rbacv1.RoleBinding

	pluginConfig, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}

	if err = decodeSecretInternalData(req, keyServiceAccount, &serviceAccount); err != nil {
		return nil, err
	}
	if err = decodeSecretInternalData(req, keyClusterRoles, &clusterRoles); err != nil {
		return nil, err
	}
	if err = decodeSecretInternalData(req, keyClusterRoleBindings, &clusterRoleBindings); err != nil {
		return nil, err
	}
	if err = decodeSecretInternalData(req, keyRoleBindings, &roleBindings); err != nil {
		return nil, err
	}

	for _, clusterRole := range clusterRoles {
		b.Logger().Info(fmt.Sprintf("deleting clusterrole '%s'", clusterRole.Name))
		if err = b.kubernetesService.DeleteClusterRole(ctx, clientSet, clusterRole); err != nil {
			return nil, err
		}
	}
	for _, clusterRoleBinding := range clusterRoleBindings {
		b.Logger().Info(fmt.Sprintf("deleting clusterrolebinding '%s'", clusterRoleBinding.Name))
		if err = b.kubernetesService.DeleteClusterRoleBinding(ctx, clientSet, clusterRoleBinding); err != nil {
			return nil, err
		}
	}
	for _, roleBinding := range roleBindings {
		b.Logger().Info(fmt.Sprintf("deleting rolebinding '%s' in '%s' namespace", roleBinding.Name, roleBinding.Namespace))
		if err = b.kubernetesService.DeleteRoleBinding(ctx, clientSet, roleBinding); err != nil {
			return nil, err
		}
	}
	if serviceAccount.Name != "" {
		b.Logger().Info(fmt.Sprintf("deleting serviceaccount '%s' in '%s' namespace", serviceAccount.Name, serviceAccount.Namespace))
		if err = b.kubernetesService.DeleteServiceAccount(ctx, clientSet, serviceAccount); err != nil {
			return nil, err
		}
	}

	return nil, nil

}

// decodeSecretInternalData extracts and decodes json strings from
// the InternalData object
func decodeSecretInternalData(req *logical.Request, key string, target interface{}) error {
	raw, _ := req.Secret.InternalData[key]
	if raw == nil {
		return fmt.Errorf("%s not found in secret internal data", key)
	}
	if err := json.Unmarshal([]byte(raw.(string)), &target); err != nil {
		return err
	}
	return nil

}
