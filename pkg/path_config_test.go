package secretsengine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {

	b, reqStorage, ctx := getTestBackend(t)

	t.Run("read empty config", func(t *testing.T) {
		_, err := testStorageRead(ctx, b, reqStorage, configPath, nil, nil)
		assert.EqualError(t, err, errorEmptyConfiguration)
	})

	t.Run("create config with missing credentials", func(t *testing.T) {
		_, err := testStorageCreate(ctx, b, reqStorage, configPath, map[string]interface{}{
			keyHost:   "https://passargada:443",
			keyCACert: `CA CERTIFICATE`,
		})
		assert.EqualError(t, err, errorMissingCredentials)
	})

	t.Run("create config with too many credentials", func(t *testing.T) {
		_, err := testStorageCreate(ctx, b, reqStorage, configPath, map[string]interface{}{
			keyHost:       "https://lapucia:8443",
			keyCACert:     "CA CERTIFICATE",
			keyClientCert: "CLIENT CERT",
			keyClientKey:  "CLIENT KEY",
			keyToken:      "TOKEN",
		})
		assert.EqualError(t, err, errorTooManyCredentials)
	})

	t.Run("create config missing ca certificate", func(t *testing.T) {
		_, err := testStorageCreate(ctx, b, reqStorage, configPath, map[string]interface{}{
			keyHost:       "https://localhost:443",
			keyClientCert: "CLIENT CERT",
			keyClientKey:  "CLIENT KEY",
		})
		assert.EqualError(t, err, errorMissingCACert)
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
			keyDefaultMaxTTL:           configs[0][keyDefaultMaxTTL].(time.Duration) / time.Second,
			keyDefaultTTL:              configs[0][keyDefaultTTL].(time.Duration) / time.Second,
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
			keyDefaultMaxTTL:           configs[1][keyDefaultMaxTTL].(time.Duration) / time.Second,
			keyDefaultTTL:              configs[1][keyDefaultTTL].(time.Duration) / time.Second,
			keyDefaultServiceAccountNs: defaultServiceAccountNs,
		})
		assert.NoError(t, err)
	})

	t.Run("delete config", func(t *testing.T) {
		_, err := testStorageDelete(ctx, b, reqStorage, configPath)
		assert.NoError(t, err)
	})

}
