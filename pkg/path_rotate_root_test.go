package secretsengine

import (
	"context"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/stretchr/testify/assert"
)

func TestRotateCredentials(t *testing.T) {

	b, reqStorage, ctx := getTestBackend(t)

	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[0])
	ctx = context.WithValue(ctx, keyFakeClient, true)

	t.Run("rotate root credentials (no bindings)", func(t *testing.T) {
		_, err := b.pathRotateRootUpdate(ctx, &logical.Request{Storage: reqStorage}, &framework.FieldData{})
		assert.EqualError(t, err, noBindingsForSubject)
	})

	objMeta := metav1.ObjectMeta{Name: getUniqueString(6)}
	subject := rbac.Subject{Name: testSubject1}
	ctx = context.WithValue(ctx, keyFakeClientObjects, []runtime.Object{
		&rbac.ClusterRoleBinding{ObjectMeta: objMeta, Subjects: []rbac.Subject{subject}},
		&rbac.RoleBinding{ObjectMeta: objMeta, Subjects: []rbac.Subject{subject}},
	})

	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[0])
	t.Run("rotate root credentials (certificate error)", func(t *testing.T) {
		_, err := b.pathRotateRootUpdate(ctx, &logical.Request{Storage: reqStorage}, &framework.FieldData{})
		assert.EqualError(t, err, emptyClientCertificate)
	})

	ctx = context.WithValue(ctx, keyFakeResponse, true)

	t.Run("rotate root credentials (certificate)", func(t *testing.T) {
		_, err := b.pathRotateRootUpdate(ctx, &logical.Request{Storage: reqStorage}, &framework.FieldData{})
		assert.NoError(t, err)
	})

	subject = rbac.Subject{Name: testSubject2}
	ctx = context.WithValue(ctx, keyFakeClientObjects, []runtime.Object{
		&rbac.ClusterRoleBinding{ObjectMeta: objMeta, Subjects: []rbac.Subject{subject}},
		&rbac.RoleBinding{ObjectMeta: objMeta, Subjects: []rbac.Subject{subject}},
	})

	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[1])
	t.Run("rotate root credentials (token)", func(t *testing.T) {
		_, err := b.pathRotateRootUpdate(ctx, &logical.Request{Storage: reqStorage}, &framework.FieldData{})
		assert.NoError(t, err)
	})

}
