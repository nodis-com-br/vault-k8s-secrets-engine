package vault_k8s_secrets_engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// PluginConfig contains all the configuration for the plugin
type PluginConfig struct {
	MaxTTL            int    `json:"max_ttl"`
	DefaultTTL        int    `json:"ttl"`
	ServiceAccountJWT string `json:"jwt"`
	CACert            string `json:"ca_cert"`
	Host              string `json:"host"`
}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: configPath,
		Fields: map[string]*framework.FieldSchema{
			keyMaxTTL: {
				Type:        framework.TypeDurationSecond,
				Description: "Time to live for the credentials returned. If not set or set to 0, will use system default.",
				Default:     "0",
			},
			keyTTL: {
				Type:        framework.TypeDurationSecond,
				Description: "Default time to live for when a user does not provide a TTL. If not set or set to 0, will use system default.",
				Default:     "0",
			},
			keyJWT: {
				Type:        framework.TypeString,
				Description: "JTW for the service account used to create and remove credentials in the Kubernetes Cluster",
				Required:    true,
			},
			keyCACert: {
				Type:        framework.TypeString,
				Description: "CA cert from the Kubernetes Cluster, to validate the connection",
				Required:    true,
			},
			keyHost: {
				Type:        framework.TypeString,
				Description: "URL for kubernetes cluster for vault to use to communicate to. [https://{url}:{port}]",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure the plugin",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Update plugin configuration",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read plugin configuration",
			},
		},
	}
}

func (b *backend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	config := PluginConfig{
		MaxTTL:            d.Get(keyMaxTTL).(int),
		DefaultTTL:        d.Get(keyTTL).(int),
		ServiceAccountJWT: d.Get(keyJWT).(string),
		CACert:            d.Get(keyCACert).(string),
		Host:              d.Get(keyHost).(string),
	}

	err := config.Validate()

	if err != nil {
		return logical.ErrorResponse("Configuration not valid: %s", err), err
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if config, err := loadPluginConfig(ctx, req.Storage); err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	} else {

		resp := &logical.Response{
			Data: map[string]interface{}{
				keyMaxTTL: config.MaxTTL,
				keyTTL:    config.DefaultTTL,
				keyJWT:    config.ServiceAccountJWT,
				keyCACert: config.CACert,
				keyHost:   config.Host,
			},
		}
		return resp, nil
	}
}

// loadPluginConfig is a helper function to simplify the loading of plugin configuration from the logical store
func loadPluginConfig(ctx context.Context, s logical.Storage) (*PluginConfig, error) {
	raw, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	conf := &PluginConfig{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// Validate validates the plugin config by checking all required values are correct
func (c *PluginConfig) Validate() error {

	_, err := url.Parse(c.Host)
	if err != nil {
		return fmt.Errorf("Host '%s' not a valid host: %s", c.Host, err)
	}

	if c.ServiceAccountJWT == "" {
		return fmt.Errorf("%s can not be empty", keyJWT)
	}

	if c.CACert == "" {
		return fmt.Errorf("%s can not be empty", keyCACert)
	}

	return nil
}
