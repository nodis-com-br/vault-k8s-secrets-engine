package vault_k8s_secrets_engine

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configPath = "config"
const rolePath = "role"
const credsPath = "creds"

const secretAccessKeyType = "service_account_token"

const keyName = "name"
const keyClusterRoleName = "cluster_role_name"
const keyNamespace = "namespace"
const keyServiceAccountToken = "service_account_token"
const keyServiceAccountName = "service_account_name"
const keyRoleBindings = "role_bindings"
const keyClusterRoleBindingName = "cluster_role_binding_name"
const keyRules = "rules"
const keyBindings = "bindings"
const keyKubeConfig = "kube_config"
const keyMaxTTL = "max_ttl"
const keyTTL = "ttl"
const keyJWT = "jwt"
const keyCACert = "ca_cert"
const keyHost = "host"

// TODO: Finish help text
const backendHelp = `
The Vault dynamic service account backend provides on-demand, dynamic 
credentials for a short-lived k8s service account
`

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

type backend struct {
	*framework.Backend
	kubernetesService KubernetesInterface
}
