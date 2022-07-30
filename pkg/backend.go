/*
 * Vault Kubernetes Secrets Engine
 * Open source kubernetes credentials manager for Hashicorp Vault
 * Copyright (c) 2022 Pedro Tonini
 * mailto:pedro DOT tonini AT hotmail DOT com
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
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

package secretsengine

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// default values
const (
	secretType                   = "rbac"
	defaultServiceAccountNs      = "kube-system"
	defaultContextNamespace      = "default"
	defaultCredentialsType       = "certificate"
	defaultListNamespaces        = false
	defaultViewNodes             = false
	defaultRSAKeyLength          = 4096
	testRSAKeyLength             = 512
	defaultWaitTime              = 1
	resourceNamePrefix           = "vault-"
	tokenSecretNameSuffix        = "-token"
	serviceAccountKind           = "ServiceAccount"
	userKind                     = "User"
	clusterRoleKind              = "ClusterRole"
	keyFakeK8sClient             = "fake_client"
	keyFakeK8sClientObjects      = "fake_client_objects"
	keyFakeResponse              = "fake_response"
	tokenServiceAccountNameClaim = "kubernetes.io/serviceaccount/service-account.name"
	backendHelp                  = `
The Vault dynamic credentials backend provides on-demand credentials 
for a short-lived k8s service account or certificate
`
)

// pathConfig constants
const (
	configPath                 = "config"
	keyToken                   = "token"
	keyClientCert              = "client_cert"
	keyClientKey               = "client_key"
	keyCACert                  = "ca_cert"
	keyHost                    = "host"
	keyDefaultServiceAccountNs = "default_serviceaccount_namespace"
	keyDefaultMaxTTL           = "default_max_ttl"
	keyDefaultTTL              = "default_ttl"
)

// pathRotateRootCredentials constants
const (
	rotateRootPath         = "rotate-root"
	pathRotateRootHelpSyn  = `Request to rotate the root credentials for the backend.`
	pathRotateRootHelpDesc = `This path attempts to rotate the root credentials for the backend.`
)

// pathRole constants
const (
	rolePath                = "role/"
	pathRoleHelpSynopsis    = `Manages the Vault role for generating kubernetes credentials.`
	pathRoleHelpDescription = `
This path allows you to read and write validRoles used to generate kubernetes RBAC objects.
You can configure a role to manage a service account by setting rules, cluster validRoles and 
namespace bindings.
`
	pathRoleListHelpSynopsis    = `List the existing validRoles in Kubernetes backend`
	pathRoleListHelpDescription = `VaultRole will be listed by the role name.`
	keyVaultRoleName            = "name"
	keyCredentialsType          = "credentials_type"
	keyBindingRules             = "binding_rules"
	keyListNamespaces           = "list_namespaces"
	keyViewNodes                = "view_nodes"
	keyServiceAccountNs         = "serviceaccount_namespace"
	keyTTL                      = "ttl"
	keyMaxTTL                   = "max_ttl"
)

// pathCredentials constants
const (
	credsPath         = "creds/"
	keyVaultCredsName = keyVaultRoleName
	keyCredsTTL       = keyTTL
)

// secret constants
const (
	keySecretHost     = keyHost
	keySecretToken    = keyToken
	keySecretCACert   = keyCACert
	keySecretUserCert = "user_cert"
	keySecretUserKey  = "user_key"
	keyKubeConfig     = "kube_config"

	// secret internal keys
	keyServiceAccount      = "serviceaccount"
	keyClusterRoles        = "clusterroles"
	keyRoleBindings        = "rolebindings"
	keyClusterRoleBindings = "clusterrolebindings"
)

// Error messages
const (
	errorEmptyConfiguration     = "configuration is empty"
	errorMissingCredentials     = "no credentials provided"
	errorTooManyCredentials     = "either token or certificates must be provided"
	errorMissingCACert          = "ca_cert can not be empty"
	errorNoBindingsForSubject   = "no bindings found for current subject"
	errorEmptyClientCertificate = "client certificate is empty"
	errorEmptyBindingRules      = "binding rules list cannot be empty"
	errorMissingRulesAndRoles   = "cluster roles or policy rules must be provided"
	errorEmptyNamespaceList     = "namespace list cannot be empty"
	errorInvalidTTLs            = "ttl cannot be greater than max_ttl"
)

type backend struct {
	*framework.Backend
	lock              sync.RWMutex
	kubernetesService KubernetesService
}

func (b *backend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.kubernetesService = KubernetesService{}
}

// Factory inits a new instance of the plugin
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	k := KubernetesService{}
	b := Backend(&k)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend instantiates the backend for the plugin
func Backend(k *KubernetesService) *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
				pathRotateRootCredentials(&b),
			},
		),
		Secrets: []*framework.Secret{
			secret(&b),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				configPath,
			},
		},
		BackendType: logical.TypeLogical,
	}
	b.kubernetesService = *k
	return &b
}
