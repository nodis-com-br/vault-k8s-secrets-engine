package secretsengine

import (
	"context"
	"encoding/json"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/stretchr/testify/assert"
)

func TestSecret(t *testing.T) {

	b, reqStorage, ctx := getTestBackend(t)
	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[0])

	objMeta := metav1.ObjectMeta{Name: getUniqueString(6)}
	sa := &corev1.ServiceAccount{ObjectMeta: objMeta, Secrets: []corev1.ObjectReference{{Name: objMeta.Name}}}
	s := &corev1.Secret{ObjectMeta: objMeta}
	cr := &rbacv1.ClusterRole{ObjectMeta: objMeta}
	rb := &rbacv1.RoleBinding{ObjectMeta: objMeta}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: objMeta}

	ctx = context.WithValue(ctx, keyFakeResponse, true)
	ctx = context.WithValue(ctx, keyFakeK8sClient, true)
	ctx = context.WithValue(ctx, keyFakeK8sClientObjects, []runtime.Object{sa, s, cr, crb, rb})

	encodedSA, _ := json.Marshal(sa)
	encodedCRs, _ := json.Marshal([]*rbacv1.ClusterRole{cr})
	encodedRBs, _ := json.Marshal([]*rbacv1.RoleBinding{rb})
	encodedCRBs, _ := json.Marshal([]*rbacv1.ClusterRoleBinding{crb})

	emptySA, _ := json.Marshal(&corev1.ServiceAccount{})
	emptyCRs, _ := json.Marshal([]*rbacv1.ClusterRole{})
	emptyRBs, _ := json.Marshal([]*rbacv1.RoleBinding{})
	emptyCRBs, _ := json.Marshal([]*rbacv1.ClusterRoleBinding{})

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

	t.Run("revoke credentials (invalid internal data)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      "invalid",
					keyClusterRoles:        "invalid",
					keyRoleBindings:        "invalid",
					keyClusterRoleBindings: "invalid",
				},
			},
		})
		assert.EqualError(t, err, "invalid character 'i' looking for beginning of value")
	})

	t.Run("revoke credentials (missing service account key)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyClusterRoles:        string(encodedCRs),
					keyRoleBindings:        string(encodedRBs),
					keyClusterRoleBindings: string(encodedCRBs),
				},
			},
		})
		assert.EqualError(t, err, keyServiceAccount+" not found in secret internal data")
	})

	t.Run("revoke credentials (missing cluster roles key)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      string(encodedSA),
					keyRoleBindings:        string(encodedRBs),
					keyClusterRoleBindings: string(encodedCRBs),
				},
			},
		})
		assert.EqualError(t, err, keyClusterRoles+" not found in secret internal data")
	})

	t.Run("revoke credentials (missing cluster role bindings key)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount: string(encodedSA),
					keyClusterRoles:   string(encodedCRs),
					keyRoleBindings:   string(encodedRBs),
				},
			},
		})
		assert.EqualError(t, err, keyClusterRoleBindings+" not found in secret internal data")
	})

	t.Run("revoke credentials (missing role bindings key)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      string(encodedSA),
					keyClusterRoles:        string(encodedCRs),
					keyClusterRoleBindings: string(encodedCRBs),
				},
			},
		})
		assert.EqualError(t, err, keyRoleBindings+" not found in secret internal data")
	})

	ctx = context.WithValue(ctx, keyFakeK8sClientObjects, []runtime.Object{})

	t.Run("revoke credentials (non existent service account)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      string(encodedSA),
					keyClusterRoles:        string(emptyCRs),
					keyRoleBindings:        string(emptyRBs),
					keyClusterRoleBindings: string(emptyCRBs),
				},
			},
		})
		assert.IsType(t, &errors.StatusError{}, err)
		assert.True(t, err.(*errors.StatusError).Status().Code == 404)
		assert.EqualError(t, err, `serviceaccounts "`+objMeta.Name+`" not found`)
	})

	ctx = addObjectToContext(ctx, sa)

	t.Run("revoke credentials (non existent service account secret)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      string(encodedSA),
					keyClusterRoles:        string(emptyCRs),
					keyRoleBindings:        string(emptyRBs),
					keyClusterRoleBindings: string(emptyCRBs),
				},
			},
		})
		assert.IsType(t, &errors.StatusError{}, err)
		assert.True(t, err.(*errors.StatusError).Status().Code == 404)
		assert.EqualError(t, err, `secrets "`+objMeta.Name+`" not found`)
	})

	t.Run("revoke credentials (non existent cluster roles)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      string(emptySA),
					keyClusterRoles:        string(encodedCRs),
					keyRoleBindings:        string(emptyRBs),
					keyClusterRoleBindings: string(emptyCRBs),
				},
			},
		})
		assert.IsType(t, &errors.StatusError{}, err)
		assert.True(t, err.(*errors.StatusError).Status().Code == 404)
		assert.EqualError(t, err, `clusterroles.rbac.authorization.k8s.io "`+objMeta.Name+`" not found`)
	})

	t.Run("revoke credentials (non existent cluster role bindings)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      string(emptySA),
					keyClusterRoles:        string(emptyCRs),
					keyRoleBindings:        string(emptyRBs),
					keyClusterRoleBindings: string(encodedCRBs),
				},
			},
		})
		assert.IsType(t, &errors.StatusError{}, err)
		assert.True(t, err.(*errors.StatusError).Status().Code == 404)
		assert.EqualError(t, err, `clusterrolebindings.rbac.authorization.k8s.io "`+objMeta.Name+`" not found`)
	})

	t.Run("revoke credentials (non existent role bindings)", func(t *testing.T) {
		_, err := b.Backend.Secrets[0].HandleRevoke(ctx, &logical.Request{
			Storage: reqStorage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					keyServiceAccount:      string(emptySA),
					keyClusterRoles:        string(emptyCRs),
					keyRoleBindings:        string(encodedRBs),
					keyClusterRoleBindings: string(emptyCRBs),
				},
			},
		})
		assert.IsType(t, &errors.StatusError{}, err)
		assert.True(t, err.(*errors.StatusError).Status().Code == 404)
		assert.EqualError(t, err, `rolebindings.rbac.authorization.k8s.io "`+objMeta.Name+`" not found`)
	})

}
