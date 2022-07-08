package secretsengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoles(t *testing.T) {

	var createdRoles []string

	b, reqStorage, ctx := getTestBackend(t)

	for i, _ := range invalidRoles {
		roleName := invalidRoles[i][keyVaultRoleName].(string)
		t.Run("create invalid role "+roleName, func(t *testing.T) {
			_, err := testStorageCreate(ctx, b, reqStorage, rolePath+roleName, invalidRoles[i])
			assert.Error(t, err)
		})
	}

	t.Run("read invalid role", func(t *testing.T) {
		_, err := testStorageRead(ctx, b, reqStorage, rolePath+invalidRoles[0][keyVaultRoleName].(string), nil, nil)
		assert.Error(t, err)
	})

	for i, _ := range validRoles {

		roleName := validRoles[i][keyVaultRoleName].(string)
		role := map[string]interface{}{}
		for k, v := range validRoles[i] {
			if k != keyVaultRoleName {
				role[k] = v
			}
		}

		t.Run("create role "+roleName, func(t *testing.T) {
			_, err := testStorageCreate(ctx, b, reqStorage, rolePath+roleName, role)
			createdRoles = append(createdRoles, roleName)
			assert.NoError(t, err)
		})

		t.Run("read role "+roleName, func(t *testing.T) {
			role[keyBindingRules] = validRoles[i][keyBindingRules].(string)
			_, err := testStorageRead(ctx, b, reqStorage, rolePath+roleName, nil, role)
			assert.NoError(t, err)
		})

	}

	t.Run("list validRoles", func(t *testing.T) {
		_, err := testStorageList(ctx, b, reqStorage, rolePath, createdRoles)
		assert.NoError(t, err)
	})

	for i, _ := range validRoles {
		roleName := validRoles[i][keyVaultRoleName].(string)
		t.Run("delete role "+roleName, func(t *testing.T) {
			_, err := testStorageDelete(ctx, b, reqStorage, rolePath+roleName)
			assert.NoError(t, err)
		})
	}

}
