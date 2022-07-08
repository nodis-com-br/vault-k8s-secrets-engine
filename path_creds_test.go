package secretsengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreds(t *testing.T) {

	b, reqStorage, ctx := getTestBackend(t)

	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[0])

	t.Run("create credentials for invalid role", func(t *testing.T) {
		_, err := testStorageRead(ctx, b, reqStorage, credsPath+"invalid", nil, nil)
		assert.Error(t, err)
	})

	for i, _ := range configs {

		_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[i])

		for j, _ := range validRoles {

			roleName := validRoles[i][keyVaultRoleName].(string)
			role := map[string]interface{}{}
			for k, v := range validRoles[j] {
				if k != keyVaultRoleName {
					role[k] = v
				}
			}
			_, _ = testStorageCreate(ctx, b, reqStorage, rolePath+roleName, role)

			t.Run("create credentials for "+roleName, func(t *testing.T) {
				_, err := testStorageRead(ctx, b, reqStorage, credsPath+roleName, nil, nil)
				assert.NoError(t, err)
			})

			t.Run("create credentials with ttl for role "+roleName, func(t *testing.T) {
				_, err := testStorageRead(ctx, b, reqStorage, credsPath+roleName, map[string]interface{}{keyTTL: 600}, nil)
				assert.NoError(t, err)
			})
		}
	}

}
