package secretsengine

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretType = "serviceaccount_token"

// default values
const (
	defaultServiceAccountNamespace = "kube-system"
	defaultContextNamespace        = "default"
	defaultResourceNamePrefix      = "vault-"
	defaultTokenSecretNameSuffix   = "-token"
	defaultServiceAccountKind      = "ServiceAccount"
	defaultClusterRoleKind         = "ClusterRole"
)

// Config constants
const (
	configPath                        = "config"
	keyToken                          = "token"
	keyCACert                         = "ca_cert"
	keyHost                           = "host"
	keyDefaultServiceAccountNamespace = "default_serviceaccount_namespace"
	keyDefaultMaxTTL                  = "default_max_ttl"
	keyDefaultTTL                     = "default_ttl"
)

// Role constants
const (
	rolePath                = "role/"
	pathRoleHelpSynopsis    = `Manages the Vault role for generating kubernetes credentials.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate kubernetes RBAC objects.
You can configure a role to manage a service account by setting rules, clusterroles and 
namespace bindings.
`
	pathRoleListHelpSynopsis    = `List the existing roles in Kubernetes backend`
	pathRoleListHelpDescription = `Role will be listed by the role name.`
	keyVaultRoleName            = "name"
	keyBindingRules             = "binding_rules"
	keyListNamespaces           = "list_namespaces"
	keyViewNodes                = "view_nodes"
	keyServiceAccountNamespace  = "serviceaccount_namespace"
	keyTTL                      = "ttl"
	keyMaxTTL                   = "max_ttl"
)

// pathCredentials constants
const (
	credsPath         = "creds/"
	keyVaultCredsName = keyVaultRoleName
	keyCredsTTL       = keyTTL
)

// Secret constants
const (
	keySecretHost   = keyHost
	keySecretToken  = keyToken
	keySecretCACert = keyCACert
	keyKubeConfig   = "kube_config"

	// Secret internal keys
	keyEncodedServiceAccount      = "encoded_serviceaccount"
	keyEncodedClusterRoles        = "encoded_clusterroles"
	keyEncodedRoleBindings        = "encoded_rolebindings"
	keyEncodedClusterRoleBindings = "encoded_clusterrolebindings"
)

const backendHelp = `
The Vault dynamic service account backend provides on-demand, dynamic 
credentials for a short-lived k8s service account
`

type backend struct {
	*framework.Backend
	kubernetesService KubernetesInterface
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
func Backend(k KubernetesInterface) *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			pathRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCredentials(&b),
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
	b.kubernetesService = k
	return &b
}
