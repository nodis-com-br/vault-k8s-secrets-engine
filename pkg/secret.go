/*
 * Vault Kubernetes Secrets Engine, open source software quality management tool.
 * Copyright (C) 2022 Pedro Tonini
 * mailto:pedro DOT tonini AT hotmail DOT com
 *
 * Vault Kubernetes Secrets Engine is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * Vault Kubernetes Secrets Engine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
func (b *backend) revokeSecret(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response,
	error) {

	pluginConfig, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}

	sa, crs, crbs, rbs, err := getExpiredResources(req)
	if err != nil {
		return nil, err
	}

	for _, cr := range crs {
		b.Logger().Info(fmt.Sprintf("deleting clusterrole '%s'", cr.Name))
		if err = b.kubernetesService.DeleteClusterRole(ctx, clientSet, cr); err != nil {
			return nil, err
		}
	}
	for _, crb := range crbs {
		b.Logger().Info(fmt.Sprintf("deleting clusterrolebinding '%s'", crb.Name))
		if err = b.kubernetesService.DeleteClusterRoleBinding(ctx, clientSet, crb); err != nil {
			return nil, err
		}
	}
	for _, rb := range rbs {
		b.Logger().Info(fmt.Sprintf("deleting rolebinding '%s' in '%s' namespace", rb.Name, rb.Namespace))
		if err = b.kubernetesService.DeleteRoleBinding(ctx, clientSet, rb); err != nil {
			return nil, err
		}
	}
	if sa.Name != "" {
		b.Logger().Info(fmt.Sprintf("deleting serviceaccount '%s' in '%s' namespace", sa.Name, sa.Namespace))
		if err = b.kubernetesService.DeleteServiceAccount(ctx, clientSet, sa); err != nil {
			return nil, err
		}
	}

	return nil, nil

}

func getExpiredResources(req *logical.Request) (*corev1.ServiceAccount, []*rbacv1.ClusterRole,
	[]*rbacv1.ClusterRoleBinding, []*rbacv1.RoleBinding, error) {

	var sa *corev1.ServiceAccount
	var crs []*rbacv1.ClusterRole
	var crbs []*rbacv1.ClusterRoleBinding
	var rbs []*rbacv1.RoleBinding

	if err := decodeSecretInternalData(req, keyServiceAccount, &sa); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := decodeSecretInternalData(req, keyClusterRoles, &crs); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := decodeSecretInternalData(req, keyClusterRoleBindings, &crbs); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := decodeSecretInternalData(req, keyRoleBindings, &rbs); err != nil {
		return nil, nil, nil, nil, err
	}

	return sa, crs, crbs, rbs, nil
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
