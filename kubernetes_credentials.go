package vault_k8s_secrets_engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func secret(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretAccessKeyType,
		Fields: map[string]*framework.FieldSchema{
			keyCACert: {
				Type:        framework.TypeString,
				Description: "CA Cert to use with the service account",
			},
			keyNamespace: {
				Type:        framework.TypeString,
				Description: "Namespace in which the service account will be created",
			},
			keyServiceAccountToken: {
				Type:        framework.TypeString,
				Description: "The token associated with the newly created service account",
			},
			keyServiceAccountName: {
				Type:        framework.TypeString,
				Description: "Name of the newly created service account",
			},
			keyClusterRoleName: {
				Type:        framework.TypeString,
				Description: "Name of the newly created cluster role",
			},
			keyClusterRoleBindingName: {
				Type:        framework.TypeString,
				Description: "Name of the newly created cluster role binding",
			},
			keyRoleBindings: {
				Type:        framework.TypeString,
				Description: "Names of the newly created role bindings",
			},
		},
		Revoke: b.revokeSecret,
	}
}

func (b *backend) createSecret(ctx context.Context, req *logical.Request, role *kubernetesRoleEntry) (*logical.Response, error) {

	b.Logger().Info(fmt.Sprintf("--- %s --- %s ---", req.DisplayName, req.EntityID))

	// reload plugin config on every call to prevent stale config
	pluginConfig, err := loadPluginConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if role.TTL <= 0 {
		role.TTL = time.Duration(pluginConfig.DefaultTTL)
	}

	if role.TTL > time.Duration(pluginConfig.MaxTTL) {
		role.TTL = time.Duration(pluginConfig.MaxTTL)
	}

	b.Logger().Info(fmt.Sprintf("creating secret for role '%s' in namespace '%s' (TTL: %d)", role.Name, role.Namespace, role.TTL))
	sa, err := b.kubernetesService.CreateServiceAccount(pluginConfig, role.Namespace)

	if err != nil {
		b.Logger().Error(fmt.Sprintf("error creating serrvice account: %s", err))
		return nil, err
	}

	s, err := b.kubernetesService.CreateServiceAccountSecret(pluginConfig, sa)
	if err != nil {
		b.Logger().Error(fmt.Sprintf("error creating secret for service account: %s", err))
		_ = b.kubernetesService.DeleteServiceAccount(pluginConfig, sa.Namespace, sa.Name)
		return nil, err
	}

	var crb *ClusterRoleBindingDetails
	var rb *RoleBindingDetails
	var rbs []RoleBindingDetails

	cr, err := b.kubernetesService.CreateClusterRole(pluginConfig, role.Rules)

	if err != nil {
		b.Logger().Error(fmt.Sprintf("Error creating cluster role: %s", err))
		return nil, err
	}

	if len(role.Bindings) > 0 {
		for _, namespace := range role.Bindings {
			rb, err = b.kubernetesService.CreateRoleBinding(pluginConfig, sa.Name, sa.Namespace, namespace, cr.Name)
			rbs = append(rbs, *rb)
		}
	} else {
		crb, err = b.kubernetesService.CreateClusterRoleBinding(pluginConfig, sa.Namespace, sa.Name, cr.Name)
	}

	dur, err := time.ParseDuration(fmt.Sprintf("%ds", role.TTL))
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("ttl: %d could not be parse due to error: %s", role.TTL, err), err)
	}

	rbsEncoded, _ := json.Marshal(rbs)

	resp := b.Secret(secretAccessKeyType).Response(map[string]interface{}{
		keyCACert:                 s.CACert,
		keyNamespace:              s.Namespace,
		keyServiceAccountToken:    s.Token,
		keyServiceAccountName:     sa.Name,
		keyClusterRoleName:        cr.Name,
		keyClusterRoleBindingName: crb.Name,
		keyRoleBindings:           rbsEncoded,
		keyKubeConfig:             generateKubeConfig(pluginConfig, s.CACert, s.Token, sa.Name),
	}, map[string]interface{}{})

	// set up TTL for secret so it gets automatically revoked
	resp.Secret.LeaseOptions.TTL = dur
	resp.Secret.LeaseOptions.MaxTTL = dur
	resp.Secret.LeaseOptions.Renewable = false
	resp.Secret.TTL = dur
	resp.Secret.MaxTTL = dur
	resp.Secret.Renewable = false

	return resp, nil
}

func (b *backend) revokeSecret(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// reload plugin config on every call to prevent stale config
	pluginConfig, err := loadPluginConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	b.Logger().Info("revoking a service account")

	namespace := d.Get(keyNamespace).(string)
	serviceAccountName := d.Get(keyServiceAccountName).(string)
	clusterRoleName := d.Get(keyClusterRoleName).(string)
	clusterRoleBindingName := d.Get(keyClusterRoleBindingName).(string)
	roleBindings := d.Get(keyRoleBindings).(string)

	b.Logger().Info(fmt.Sprintf("deleting secret for service account '%s' in namespace '%s'", serviceAccountName, namespace))
	err = b.kubernetesService.DeleteServiceAccountSecret(pluginConfig, namespace, serviceAccountName)
	if err != nil {
		return nil, err
	}

	b.Logger().Info(fmt.Sprintf("deleting cluster role '%s'", clusterRoleName))
	err = b.kubernetesService.DeleteClusterRole(pluginConfig, clusterRoleName)
	if err != nil {
		return nil, err
	}

	if clusterRoleBindingName != "" {
		b.Logger().Info(fmt.Sprintf("deleting cluster role binding '%s'", clusterRoleBindingName))
		err = b.kubernetesService.DeleteClusterRoleBinding(pluginConfig, clusterRoleBindingName)
		if err != nil {
			return nil, err
		}
	}

	if roleBindings != "" {
		rbs := make([]RoleBindingDetails, 0)
		_ = json.Unmarshal([]byte(roleBindings), &rbs)
		for _, rb := range rbs {
			b.Logger().Info(fmt.Sprintf("deleting role binding '%s' in namespace '%s'", rb.Name, rb.Namespace))
			err = b.kubernetesService.DeleteRoleBinding(pluginConfig, rb.Namespace, rb.Name)
			if err != nil {
				return nil, err
			}
		}
	}

	b.Logger().Info(fmt.Sprintf("deleting service account '%s' in namespace '%s'", serviceAccountName, namespace))
	err = b.kubernetesService.DeleteServiceAccount(pluginConfig, namespace, serviceAccountName)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(secretAccessKeyType).Response(map[string]interface{}{
		keyServiceAccountName: serviceAccountName,
	}, map[string]interface{}{})

	return resp, nil
}

func generateKubeConfig(pluginConfig *PluginConfig, caCert string, token string, name string) string {
	return fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: %s
contexts:
- context:
    cluster: %s
    user: %s
  name: %s
current-context: %s
kind: Config
preferences: {}
users:
- name: %s
  user:
    token: %s`, base64Encode(caCert), pluginConfig.Host, name, name, name, name, name, name, token)
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
