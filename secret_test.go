package secretsengine

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/stretchr/testify/assert"
)

func TestSecret(t *testing.T) {

	b, reqStorage, ctx := getTestBackend(t)

	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[0])

	encodedSA, _ := json.Marshal(corev1.ServiceAccount{Secrets: []corev1.ObjectReference{{}}})
	encodedCRs, _ := json.Marshal([]*rbacv1.ClusterRole{{}})
	encodedRBs, _ := json.Marshal([]*rbacv1.RoleBinding{{}})
	encodedCRBs, _ := json.Marshal([]*rbacv1.ClusterRoleBinding{{}})

	t.Run("revoke credentials", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      string(encodedSA),
					keyClusterRoles:        string(encodedCRs),
					keyRoleBindings:        string(encodedRBs),
					keyClusterRoleBindings: string(encodedCRBs),
				},
			},
		})
		assert.NoError(t, err)
	})

}
