package secretsengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	b, reqStorage, ctx := getTestBackend(t)

	t.Run("read empty config", func(t *testing.T) {
		_, err := testStorageRead(ctx, b, reqStorage, configPath, nil, nil)
		assert.Error(t, err)
	})

	t.Run("create config with missing credentials", func(t *testing.T) {
		_, err := testStorageCreate(ctx, b, reqStorage, configPath, map[string]interface{}{
			keyHost:   "https://localhost:443",
			keyCACert: `CA CERTIFICATE`,
		})
		assert.Error(t, err)
	})

	t.Run("create config with too much credentials", func(t *testing.T) {
		_, err := testStorageCreate(ctx, b, reqStorage, configPath, map[string]interface{}{
			keyHost:       "https://localhost:443",
			keyCACert:     `CA CERTIFICATE`,
			keyClientCert: clientCert,
			keyClientKey:  clientKey,
			keyToken:      "TOKEN",
		})
		assert.Error(t, err)
	})

	t.Run("create config missing ca certificate", func(t *testing.T) {
		_, err := testStorageCreate(ctx, b, reqStorage, configPath, map[string]interface{}{
			keyHost:       "https://localhost:443",
			keyClientCert: clientCert,
			keyClientKey:  clientKey,
		})
		assert.Error(t, err)
	})

	t.Run("create config", func(t *testing.T) {
		_, err := testStorageCreate(ctx, b, reqStorage, configPath, configs[0])
		assert.NoError(t, err)
	})

	t.Run("read config", func(t *testing.T) {
		_, err := testStorageRead(ctx, b, reqStorage, configPath, nil, map[string]interface{}{
			keyHost:                    configs[0][keyHost],
			keyCACert:                  configs[0][keyCACert],
			keyClientCert:              configs[0][keyClientCert],
			keyDefaultMaxTTL:           configs[0][keyDefaultMaxTTL],
			keyDefaultTTL:              configs[0][keyDefaultTTL],
			keyDefaultServiceAccountNs: defaultServiceAccountNs,
		})
		assert.NoError(t, err)
	})

	t.Run("update config to token", func(t *testing.T) {
		_, err := testStorageUpdate(ctx, b, reqStorage, configPath, configs[1])
		assert.NoError(t, err)
	})

	t.Run("read updated config", func(t *testing.T) {
		_, err := testStorageRead(ctx, b, reqStorage, configPath, nil, map[string]interface{}{
			keyHost:                    configs[1][keyHost],
			keyCACert:                  configs[1][keyCACert],
			keyClientCert:              configs[1][keyClientCert],
			keyDefaultMaxTTL:           configs[1][keyDefaultMaxTTL],
			keyDefaultTTL:              configs[1][keyDefaultTTL],
			keyDefaultServiceAccountNs: defaultServiceAccountNs,
		})
		assert.NoError(t, err)
	})

	t.Run("delete config", func(t *testing.T) {
		_, err := testStorageDelete(ctx, b, reqStorage, configPath)
		assert.NoError(t, err)
	})

}
