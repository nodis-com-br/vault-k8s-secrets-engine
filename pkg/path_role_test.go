package secretsengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoles(t *testing.T) {

	var createdRoles []string
	b, reqStorage, ctx := getTestBackend(t)

	for _, role := range invalidRoles {
		t.Run("create invalid role "+role.Name, func(t *testing.T) {
			_, err := testStorageCreate(ctx, b, reqStorage, rolePath+role.Name, role.Value)
			assert.EqualError(t, err, role.Error)
		})
	}

	t.Run("read invalid role", func(t *testing.T) {
		_, err := testStorageRead(ctx, b, reqStorage, rolePath+"invalid", nil, nil)
		assert.Error(t, err)
	})

	for _, role := range validRoles {

		t.Run("create role "+role.Name, func(t *testing.T) {
			_, err := testStorageCreate(ctx, b, reqStorage, rolePath+role.Name, role.Value)
			assert.NoError(t, err)
		})

		t.Run("read role "+role.Name, func(t *testing.T) {
			role.Value[keyBindingRules] = role.Value[keyBindingRules].(string)
			_, err := testStorageRead(ctx, b, reqStorage, rolePath+role.Name, nil, role.Value)
			assert.NoError(t, err)
		})

	}

	t.Run("list validRoles", func(t *testing.T) {
		_, err := testStorageList(ctx, b, reqStorage, rolePath, createdRoles)
		assert.NoError(t, err)
	})

	for _, role := range validRoles {
		t.Run("delete role "+role.Name, func(t *testing.T) {
			_, err := testStorageDelete(ctx, b, reqStorage, rolePath+role.Name)
			assert.NoError(t, err)
		})
	}

}
