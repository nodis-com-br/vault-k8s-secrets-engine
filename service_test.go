package secretsengine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestService(t *testing.T) {

	b, reqStorage, _ := getTestBackend(t)
	ctx := context.Background()
	_, _ = testStorageCreate(ctx, b, reqStorage, configPath, configs[0])
	pluginConfig, _ := getConfig(ctx, reqStorage)

	t.Run("get kubernetes client", func(t *testing.T) {
		_, err := getClientset(ctx, pluginConfig)
		assert.NoError(t, err)
	})

	t.Run("get kubernetes certificates client", func(t *testing.T) {
		_, err := getCertificatesV1Client(ctx, pluginConfig)
		assert.NoError(t, err)
	})

}
