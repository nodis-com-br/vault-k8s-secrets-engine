package secretsengine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreds(t *testing.T) {

	b, reqStorage, ctx := getTestBackend(t)
	ctx = context.WithValue(ctx, keyFakeClient, true)
	ctx = context.WithValue(ctx, keyFakeResponse, true)
	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[0])

	t.Run("create credentials for nil role", func(t *testing.T) {
		_, err := testStorageRead(ctx, b, reqStorage, credsPath+"invalid", nil, nil)
		assert.EqualError(t, err, "error retrieving role: role is nil")
	})

	for i, _ := range configs {

		_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[i])

		for _, role := range validRoles {

			_, _ = testStorageCreate(ctx, b, reqStorage, rolePath+role.Name, role.Value)

			t.Run("create credentials for "+role.Name, func(t *testing.T) {
				_, err := testStorageRead(ctx, b, reqStorage, credsPath+role.Name, nil, nil)
				assert.NoError(t, err)
			})

			t.Run("create credentials with ttl for role "+role.Name, func(t *testing.T) {
				_, err := testStorageRead(ctx, b, reqStorage, credsPath+role.Name, map[string]interface{}{keyTTL: 600}, nil)
				assert.NoError(t, err)
			})

		}
	}

}
