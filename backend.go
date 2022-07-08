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
	secretType              = "rbac"
	defaultServiceAccountNs = "kube-system"
	defaultContextNamespace = "default"
	defaultCredentialsType  = "certificate"
	defaultListNamespaces   = false
	defaultViewNodes        = false
	sleepSeconds            = 1
	rsaKeyLength            = 4096
	resourceNamePrefix      = "vault-"
	tokenSecretNameSuffix   = "-token"
	serviceAccountKind      = "ServiceAccount"
	userKind                = "User"
	clusterRoleKind         = "ClusterRole"
	keyTesting              = "testing"
)

// Config constants
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

const (
	rotateRootCredentialsPath = "rotate-root"
)

// VaultRole constants
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

// Secret constants
const (
	keySecretHost     = keyHost
	keySecretToken    = keyToken
	keySecretCACert   = keyCACert
	keySecretUserCert = "user_cert"
	keySecretUserKey  = "user_key"
	keyKubeConfig     = "kube_config"

	// Secret internal keys
	keyServiceAccount      = "serviceaccount"
	keyClusterRoles        = "clusterroles"
	keyRoleBindings        = "rolebindings"
	keyClusterRoleBindings = "clusterrolebindings"
)

const backendHelp = `
The Vault dynamic service account backend provides on-demand, dynamic 
credentials for a short-lived k8s service account
`

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
