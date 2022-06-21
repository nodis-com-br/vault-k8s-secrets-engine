package secretsengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	rbac "k8s.io/api/rbac/v1"
	"time"
)

type Secret struct {
	ServiceAccount             *ServiceAccount
	Host                       string `json:"host"`
	KubeConfig                 string `json:"kube_config"`
	EncodedClusterRoles        string `json:"encoded_clusterroles"`
	EncodedRoleBindings        string `json:"encoded_rolebindings"`
	EncodedClusterRoleBindings string `json:"encoded_clusterrolebindings"`
}

func secret(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretType,
		Fields: map[string]*framework.FieldSchema{
			keySecretToken: {
				Type:        framework.TypeString,
				Description: "Token for authentication",
			},
			keySecretCACert: {
				Type:        framework.TypeString,
				Description: "Cluster CA Certificate for validation",
			}, keySecretHost: {
				Type:        framework.TypeString,
				Description: "Cluster API address",
			},
			keyKubeConfig: {
				Type:        framework.TypeString,
				Description: "Rendered kubernetes config manifest",
			},
		},
		Revoke: b.revokeSecret,
	}
}

func (b *backend) createSecret(ctx context.Context, req *logical.Request, role *Role) (*Secret, error) {

	createdRoleBindings := make([]RoleBinding, 0)
	createdClusterRoles := make([]ClusterRole, 0)
	createdClusterRoleBindings := make([]ClusterRoleBinding, 0)
	contextNamespace := defaultContextNamespace

	// reload plugin config on every call to prevent stale config
	pluginConfig, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if role.ServiceAccountNamespace == "" {
		role.ServiceAccountNamespace = pluginConfig.DefaultServiceAccountNamespace
	}

	if role.TTL == 0 {
		role.TTL = pluginConfig.DefaultTTL
	}

	if role.MaxTTL == 0 {
		role.MaxTTL = pluginConfig.DefaultMaxTTL
	}

	b.Logger().Info(fmt.Sprintf("creating serviceaccount for %s in '%s' namespace with duration of %ds", req.DisplayName, role.ServiceAccountNamespace, role.TTL/time.Second))
	serviceAccount, err := b.kubernetesService.CreateServiceAccount(pluginConfig, role.ServiceAccountNamespace)
	if err != nil {
		return nil, err
	}

	builtInRule := BindingRule{
		Namespaces: []string{"*"},
		Rules:      []rbac.PolicyRule{},
	}
	if role.ListNamespaces {
		builtInRule.Rules = append(builtInRule.Rules, rbac.PolicyRule{
			APIGroups: []string{""},
			Verbs:     []string{"list"},
			Resources: []string{"namespaces"},
		})
	}
	if role.ViewNodes {
		builtInRule.Rules = append(builtInRule.Rules, rbac.PolicyRule{
			APIGroups: []string{""},
			Verbs:     []string{"list", "get"},
			Resources: []string{"nodes"},
		})
	}

	if len(builtInRule.Rules) > 0 {
		role.BindingRules = append(role.BindingRules, builtInRule)
	}

	for _, bindingRule := range role.BindingRules {
		if len(bindingRule.Rules) > 0 {
			b.Logger().Info(fmt.Sprintf("creating clusterrole for %s", req.DisplayName))
			clusterRole, err := b.kubernetesService.CreateClusterRole(pluginConfig, bindingRule.Rules)
			if err != nil {
				return nil, err
			}
			createdClusterRoles = append(createdClusterRoles, *clusterRole)
			bindingRule.ClusterRoles = append(bindingRule.ClusterRoles, clusterRole.Name)
		}
		for _, name := range bindingRule.ClusterRoles {
			clusterRole := &ClusterRole{name}
			if bindingRule.Namespaces[0] == "*" {
				b.Logger().Info(fmt.Sprintf("creating clusterrolebinding to '%s' for %s", name, req.DisplayName))
				clusterRoleBinding, err := b.kubernetesService.CreateClusterRoleBinding(pluginConfig, clusterRole, serviceAccount)
				if err != nil {
					return nil, err
				}
				createdClusterRoleBindings = append(createdClusterRoleBindings, *clusterRoleBinding)
			} else {
				for _, namespace := range bindingRule.Namespaces {
					b.Logger().Info(fmt.Sprintf("creating rolebinding to '%s' for %s in '%s' namespace", name, req.DisplayName, namespace))
					roleBinding, err := b.kubernetesService.CreateRoleBinding(pluginConfig, namespace, clusterRole, serviceAccount)
					if err != nil {
						return nil, err
					}
					createdRoleBindings = append(createdRoleBindings, *roleBinding)
				}
			}
		}
	}

	encodedClusterRoles, _ := json.Marshal(createdClusterRoles)
	encodedRoleBindings, _ := json.Marshal(createdRoleBindings)
	encodedClusterRoleBindings, _ := json.Marshal(createdClusterRoleBindings)

	return &Secret{
		ServiceAccount:             serviceAccount,
		Host:                       pluginConfig.Host,
		KubeConfig:                 generateKubeConfig(pluginConfig.Host, serviceAccount.Secret.CACert, serviceAccount.Secret.Token, serviceAccount.Name, contextNamespace),
		EncodedClusterRoles:        string(encodedClusterRoles),
		EncodedRoleBindings:        string(encodedRoleBindings),
		EncodedClusterRoleBindings: string(encodedClusterRoleBindings),
	}, nil

}

func (b *backend) revokeSecret(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// reload plugin config on every call to prevent stale config
	pluginConfig, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	clusterRoles := make([]ClusterRole, 0)
	if err = decodeSecretInternalData(req, keyEncodedClusterRoles, &clusterRoles); err != nil {
		return nil, err
	}
	for _, clusterRole := range clusterRoles {
		b.Logger().Info(fmt.Sprintf("deleting clusterrole '%s'", clusterRole.Name))
		if err = b.kubernetesService.DeleteClusterRole(pluginConfig, &clusterRole); err != nil {
			return nil, err
		}
	}

	clusterRoleBindings := make([]ClusterRoleBinding, 0)
	if err = decodeSecretInternalData(req, keyEncodedClusterRoleBindings, &clusterRoleBindings); err != nil {
		return nil, err
	}
	for _, clusterRoleBinding := range clusterRoleBindings {
		b.Logger().Info(fmt.Sprintf("deleting clusterrolebinding '%s'", clusterRoleBinding.Name))
		if err = b.kubernetesService.DeleteClusterRoleBinding(pluginConfig, &clusterRoleBinding); err != nil {
			return nil, err
		}
	}

	roleBindings := make([]RoleBinding, 0)
	if err = decodeSecretInternalData(req, keyEncodedRoleBindings, &roleBindings); err != nil {
		return nil, err
	}
	for _, roleBinding := range roleBindings {
		b.Logger().Info(fmt.Sprintf("deleting rolebinding '%s' in '%s' namespace", roleBinding.Name, roleBinding.Namespace))
		if err = b.kubernetesService.DeleteRoleBinding(pluginConfig, &roleBinding); err != nil {
			return nil, err
		}
	}

	serviceAccount := ServiceAccount{}
	if err = decodeSecretInternalData(req, keyEncodedServiceAccount, &serviceAccount); err != nil {
		return nil, err
	}
	b.Logger().Info(fmt.Sprintf("deleting serviceaccount '%s' in '%s' namespace", serviceAccount.Name, serviceAccount.Namespace))
	if err = b.kubernetesService.DeleteServiceAccount(pluginConfig, &serviceAccount); err != nil {
		return nil, err
	}

	resp := b.Secret(secretType).Response(map[string]interface{}{}, map[string]interface{}{})

	return resp, nil

}

func generateKubeConfig(host string, caCert string, token string, name string, namespace string) string {
	return fmt.Sprintf(`---
apiVersion: v1
kind: Config
clusters:
  - cluster:
      certificate-authority-data: %s
      server: %s
    name: %s
contexts:
  - context:
      cluster: %s
      namespace: %s      
      user: %s
    name: %s
current-context: %s
users:
  - name: %s
    user:
      token: %s`, base64Encode(caCert), host, name, name, namespace, name, name, name, name, token)
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func decodeSecretInternalData(req *logical.Request, key string, target interface{}) error {
	if raw, ok := req.Secret.InternalData[key]; ok {
		if err := json.Unmarshal([]byte(raw.(string)), &target); err != nil {
			return err
		}
		return nil
	} else {
		return fmt.Errorf("#{%s} key not found in secret internal data", key)
	}
}
