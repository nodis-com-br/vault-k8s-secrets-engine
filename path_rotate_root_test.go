package secretsengine

import (
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/stretchr/testify/assert"
)

func TestRotateCredentials(t *testing.T) {

	b, reqStorage, ctx := getTestBackend(t)

	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[0])

	t.Run("rotate root credentials", func(t *testing.T) {
		_, err := b.rotateRootCredentials(ctx, &logical.Request{Storage: reqStorage}, &framework.FieldData{})
		assert.NoError(t, err)
	})

	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[1])

	t.Run("rotate root credentials", func(t *testing.T) {
		_, err := b.rotateRootCredentials(ctx, &logical.Request{Storage: reqStorage}, &framework.FieldData{})
		assert.Error(t, err)
	})

}
