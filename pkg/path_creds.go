/*
 * Vault Kubernetes Secrets Engine
 * Open source kubernetes credentials manager for Hashicorp Vault
 * Copyright (c) 2022 Pedro Tonini
 * Contact: pedro.tonini@hotmail.com
 *
 * Vault Kubernetes Secrets Engine is free software;
 * you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation;
 * either version 3 of the License, or (at your option)
 * any later version.
 *
 * Vault Kubernetes Secrets Engine is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 */

package secretsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Credentials contains all the configuration of the
// generated credentials
type Credentials struct {
	// External data
	Secret          *corev1.Secret
	UserCertificate *UserCertificate
	Host            string `json:"host"`
	CACert          string `json:"ca_cert"`
	KubeConfig      string `json:"kube_config"`
	// Internal data
	ServiceAccount      string `json:"serviceaccount"`
	ClusterRoles        string `json:"clusterroles"`
	RoleBindings        string `json:"rolebindings"`
	ClusterRoleBindings string `json:"clusterrolebindings"`
}

// UserCertificate stores the certificate and
// private key for x509 authentication
type UserCertificate struct {
	Username    string `json:"username"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"-"`
}

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
				Type: framework.TypeDurationSecond,
				Description: "The time to live for the token in seconds. If not set or set to 0, will use system " +
					"default.",
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

// pathCredentialsRead retrieves the role configuration
// and generate new credentials
func (b *backend) pathCredentialsRead(ctx context.Context, req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {

	var secretToken string
	var userCertificate string
	var userKey string

	role, err := getRole(ctx, req.Storage, rolePath+d.Get(keyVaultCredsName).(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("error retrieving role: role is nil")
	}

	if credentialsTTL, ok := d.GetOk(keyCredsTTL); ok {
		role.TTL = time.Duration(credentialsTTL.(int)) * time.Second
	}

	creds, err := createCredentials(ctx, b, req, role)
	if err != nil {
		return nil, err
	}

	if creds.Secret != nil {
		secretToken = string(creds.Secret.Data[keySecretToken])
	}
	if creds.UserCertificate != nil {
		userCertificate = creds.UserCertificate.Certificate
		userKey = creds.UserCertificate.PrivateKey
	}

	resp := b.Secret(secretType).Response(map[string]interface{}{
		keySecretToken:    secretToken,
		keySecretUserCert: userCertificate,
		keySecretUserKey:  userKey,
		keySecretHost:     creds.Host,
		keySecretCACert:   creds.CACert,
		keyKubeConfig:     creds.KubeConfig,
	}, map[string]interface{}{
		keyServiceAccount:      creds.ServiceAccount,
		keyClusterRoles:        creds.ClusterRoles,
		keyRoleBindings:        creds.RoleBindings,
		keyClusterRoleBindings: creds.ClusterRoleBindings,
	})

	// set up TTL for secret so it gets automatically revoked
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	resp.Secret.Renewable = false

	return resp, nil

}

// createCredentials generate new credentials based
// on the role settings
func createCredentials(ctx context.Context, b *backend, req *logical.Request, role *VaultRole) (*Credentials, error) {

	var sa = &corev1.ServiceAccount{}
	var sas *corev1.Secret
	var uc *UserCertificate
	var sbj rbacv1.Subject
	var c string
	var rbs []*rbacv1.RoleBinding
	var crb []*rbacv1.ClusterRoleBinding
	var crs []*rbacv1.ClusterRole
	var cn = defaultContextNamespace

	// reload plugin config on every call to prevent stale config
	pluginConfig, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	clientSet, err := getClientset(ctx, pluginConfig)
	certClientSet, _ := getCertificatesV1Client(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}

	if role.ServiceAccountNamespace == "" {
		role.ServiceAccountNamespace = pluginConfig.DefaultServiceAccountNamespace
	}

	if role.TTL == 0 {
		if pluginConfig.DefaultTTL == 0 {
			role.TTL = b.System().MaxLeaseTTL()
		} else {
			role.TTL = pluginConfig.DefaultTTL
		}
	}

	if role.MaxTTL == 0 {
		if pluginConfig.DefaultMaxTTL == 0 {
			role.MaxTTL = b.System().MaxLeaseTTL()
		} else {
			role.MaxTTL = pluginConfig.DefaultMaxTTL
		}
	}

	b.Logger().Info(fmt.Sprintf("creating %s for %s", role.CredentialType, req.DisplayName))
	if role.CredentialType == "token" {
		sa, sas, err = b.kubernetesService.CreateServiceAccount(ctx, clientSet, role.ServiceAccountNamespace)
		if err != nil {
			return nil, err
		}
		sbj = rbacv1.Subject{
			Kind:      serviceAccountKind,
			Name:      sa.Name,
			Namespace: sa.Namespace,
		}
	}
	if role.CredentialType == "certificate" {
		sbjName := req.DisplayName + "-" + getUniqueString(6)
		es := int32(role.TTL / time.Second)
		key, csr := createKeyAndCertificateRequest(sbjName, defaultRSAKeyLength)
		if c, err = b.kubernetesService.SignCertificateRequest(ctx, certClientSet, sbjName, csr, &es); err != nil {
			return nil, err
		}
		uc = &UserCertificate{
			Username:    sbjName,
			Certificate: base64Encode(c),
			PrivateKey:  base64Encode(key),
		}
		sbj = rbacv1.Subject{
			Kind: userKind,
			Name: sbjName,
		}
	}

	builtInRule := &BindingRule{
		Namespaces:  []string{"*"},
		PolicyRules: []rbacv1.PolicyRule{},
	}
	if role.ListNamespaces {
		builtInRule.PolicyRules = append(builtInRule.PolicyRules, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Verbs:     []string{"list"},
			Resources: []string{"namespaces"},
		})
	}
	if role.ViewNodes {
		builtInRule.PolicyRules = append(builtInRule.PolicyRules, rbacv1.PolicyRule{
			APIGroups: []string{""},
			Verbs:     []string{"list", "get"},
			Resources: []string{"nodes"},
		})
	}

	if len(builtInRule.PolicyRules) > 0 {
		role.BindingRules = append(role.BindingRules, *builtInRule)
	}

	for _, bindingRule := range role.BindingRules {
		if len(bindingRule.PolicyRules) > 0 {
			b.Logger().Info(fmt.Sprintf("creating clusterrole for %s", req.DisplayName))
			clusterRole, err := b.kubernetesService.CreateClusterRole(ctx, clientSet, bindingRule.PolicyRules)
			if err != nil {
				return nil, err
			}
			crs = append(crs, clusterRole)
			bindingRule.ClusterRoles = append(bindingRule.ClusterRoles, clusterRole.Name)
		}
		for _, name := range bindingRule.ClusterRoles {
			roleRef := rbacv1.RoleRef{
				Kind: clusterRoleKind,
				Name: name,
			}
			if bindingRule.Namespaces[0] == "*" {
				b.Logger().Info(fmt.Sprintf("creating clusterrolebinding to '%s' for %s", name, req.DisplayName))
				clusterRoleBinding, err := b.kubernetesService.CreateClusterRoleBinding(ctx, clientSet, &roleRef, &sbj)
				if err != nil {
					return nil, err
				}
				crb = append(crb, clusterRoleBinding)
			} else {
				for _, namespace := range bindingRule.Namespaces {
					b.Logger().Info(fmt.Sprintf("creating rolebinding to '%s' for %s in '%s' namespace", name,
						req.DisplayName, namespace))
					roleBinding, err := b.kubernetesService.CreateRoleBinding(ctx, clientSet, namespace, &roleRef, &sbj)
					if err != nil {
						return nil, err
					}
					rbs = append(rbs, roleBinding)
				}
			}
		}
	}

	b.Logger().Info(fmt.Sprintf("creating kube config for '%s'", req.DisplayName))
	kubeConfig := createKubeConfig(pluginConfig.Host, pluginConfig.CACert, cn, sa, sas, uc)

	encodedServiceAccount, _ := json.Marshal(sa)
	encodedClusterRoles, _ := json.Marshal(crs)
	encodedRoleBindings, _ := json.Marshal(rbs)
	encodedClusterRoleBindings, _ := json.Marshal(crb)

	return &Credentials{
		Secret:              sas,
		UserCertificate:     uc,
		KubeConfig:          kubeConfig,
		Host:                pluginConfig.Host,
		CACert:              pluginConfig.CACert,
		ServiceAccount:      string(encodedServiceAccount),
		ClusterRoles:        string(encodedClusterRoles),
		RoleBindings:        string(encodedRoleBindings),
		ClusterRoleBindings: string(encodedClusterRoleBindings),
	}, nil

}

// createKubeConfig is a helper functions for rendering a
// kubeconfig file with the generated credentials
func createKubeConfig(h string, ca string, ns string, sa *corev1.ServiceAccount, s *corev1.Secret,
	c *UserCertificate) string {

	name := "~"
	token := "~"
	certificate := "~"
	privateKey := "~"

	if sa.Name != "" {
		name = sa.Name
		token = string(s.Data["token"])
	}
	if c != nil {
		name = c.Username
		certificate = c.Certificate
		privateKey = c.PrivateKey
	}

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
      ns: %s      
      user: %s
    name: %s
current-context: %s
users:
  - name: %s
    user:
      token: %s
      client-certificate-data: %s
      client-key-data: %s`, base64Encode(ca), h, name, name, ns, name, name, name, name, token, certificate, privateKey)
}
