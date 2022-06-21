package secretsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Config contains all the configuration for the plugin
type Config struct {
	Token                          string        `json:"token"`
	CACert                         string        `json:"ca_cert"`
	Host                           string        `json:"host"`
	DefaultServiceAccountNamespace string        `json:"default_serviceaccount_namespace"`
	DefaultTTL                     time.Duration `json:"default_ttl"`
	DefaultMaxTTL                  time.Duration `json:"default_max_ttl"`
}

// Validate validates the plugin config by checking all required values are correct
func (c *Config) Validate() error {

	_, err := url.Parse(c.Host)
	if err != nil {
		return fmt.Errorf("%s '%s' is invalid: %s", keyHost, c.Host, err)
	}

	if c.Token == "" {
		return fmt.Errorf("%s can not be empty", keyToken)
	}

	if c.CACert == "" {
		return fmt.Errorf("%s can not be empty", keyCACert)
	}

	return nil

}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: configPath,
		Fields: map[string]*framework.FieldSchema{
			keyToken: {
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
			keyDefaultServiceAccountNamespace: {
				Type:        framework.TypeString,
				Description: "Default namespace of the role ServiceAccount",
				Default:     defaultServiceAccountNamespace,
			},
			keyDefaultTTL: {
				Type:        framework.TypeDurationSecond,
				Description: "Default time to live for when a user does not provide a TTL. If not set or set to 0, will use system default.",
				Default:     "0",
			},
			keyDefaultMaxTTL: {
				Type:        framework.TypeDurationSecond,
				Description: "Time to live for the credentials returned. If not set or set to 0, will use system default.",
				Default:     "0",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Configure the plugin",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Update plugin configuration",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read plugin configuration",
			},
		},
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	config := Config{
		Token:                          d.Get(keyToken).(string),
		CACert:                         d.Get(keyCACert).(string),
		Host:                           d.Get(keyHost).(string),
		DefaultServiceAccountNamespace: d.Get(keyDefaultServiceAccountNamespace).(string),
		DefaultTTL:                     time.Duration(d.Get(keyDefaultTTL).(int)) * time.Second,
		DefaultMaxTTL:                  time.Duration(d.Get(keyDefaultMaxTTL).(int)) * time.Second,
	}

	err := config.Validate()

	if err != nil {
		return logical.ErrorResponse("configuration invalid: %s", err), err
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

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if config, err := getConfig(ctx, req.Storage); err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	} else {
		resp := &logical.Response{
			Data: map[string]interface{}{
				keyDefaultMaxTTL:                  config.DefaultMaxTTL / time.Second,
				keyDefaultTTL:                     config.DefaultTTL / time.Second,
				keyCACert:                         config.CACert,
				keyHost:                           config.Host,
				keyDefaultServiceAccountNamespace: config.DefaultServiceAccountNamespace,
			},
		}
		return resp, nil
	}
}

// getConfig is a helper function to simplify the loading of plugin configuration from the logical store
func getConfig(ctx context.Context, s logical.Storage) (*Config, error) {
	raw, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	conf := &Config{}
	if err := json.Unmarshal(raw.Value, conf); err != nil {
		return nil, err
	}
	return conf, nil
}
