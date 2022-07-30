/*
 * Vault Kubernetes Secrets Engine
 * Open source kubernetes credentials manager for Hashicorp Vault
 * Copyright (c) 2022 Pedro Tonini
 * Contact: pedro.tonini@hotmail.com
 *
 * Vault Kubernetes Secrets Engine is free software;
 * you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation;
 * either version 3 of the License, or (at your option)
 * any later version.
 *
 * Vault Kubernetes Secrets Engine is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 */

package secretsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Config contains all the configuration options for the plugin
type Config struct {
	Token                          string        `json:"token"`
	ClientCert                     string        `json:"client_cert"`
	ClientKey                      string        `json:"client_key"`
	CACert                         string        `json:"ca_cert"`
	Host                           string        `json:"host"`
	DefaultServiceAccountNamespace string        `json:"default_sa_namespace"`
	DefaultTTL                     time.Duration `json:"default_ttl"`
	DefaultMaxTTL                  time.Duration `json:"default_max_ttl"`
}

// Validate validates the plugin config by checking all required values are correct
func (c *Config) Validate() error {

	if c.Token == "" && c.ClientCert == "" && c.ClientKey == "" {
		return fmt.Errorf(errorMissingCredentials)
	}

	if c.Token != "" && (c.ClientCert != "" || c.ClientKey != "") {
		return fmt.Errorf(errorTooManyCredentials)
	}

	if c.CACert == "" {
		return fmt.Errorf(errorMissingCACert)
	}

	return nil
}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: configPath,
		Fields: map[string]*framework.FieldSchema{
			keyToken: {
				Type: framework.TypeString,
				Description: "Token for the service account used to create and remove credentials in the " +
					"Kubernetes Cluster",
			},
			keyClientCert: {
				Type:        framework.TypeString,
				Description: "Client certificate for the Kubernetes Cluster",
			},
			keyClientKey: {
				Type:        framework.TypeString,
				Description: "Client private key from the Kubernetes Cluster",
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
			keyDefaultServiceAccountNs: {
				Type:        framework.TypeString,
				Description: "Default namespace of the role ServiceAccount",
				Default:     defaultServiceAccountNs,
			},
			keyDefaultTTL: {
				Type: framework.TypeDurationSecond,
				Description: "Default time to live for when a user does not provide a TTL. If not set or set to 0, " +
					"will use system default.",
				Default: "0",
			},
			keyDefaultMaxTTL: {
				Type: framework.TypeDurationSecond,
				Description: "Time to live for the credentials returned. If not set or set to 0, will use system " +
					"default.",
				Default: "0",
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
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				Summary:  "Delete plugin configuration",
			},
		},
		HelpSynopsis:    "",
		HelpDescription: "",
	}
}

// pathConfigWrite saves the configuration on the storage backend
func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response,
	error) {

	config := Config{
		Token:                          d.Get(keyToken).(string),
		ClientCert:                     d.Get(keyClientCert).(string),
		ClientKey:                      d.Get(keyClientKey).(string),
		CACert:                         d.Get(keyCACert).(string),
		Host:                           d.Get(keyHost).(string),
		DefaultServiceAccountNamespace: d.Get(keyDefaultServiceAccountNs).(string),
		DefaultTTL:                     time.Duration(d.Get(keyDefaultTTL).(int)) * time.Second,
		DefaultMaxTTL:                  time.Duration(d.Get(keyDefaultMaxTTL).(int)) * time.Second,
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	entry, _ := logical.StorageEntryJSON(configPath, config)
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

// pathConfigRead retrieves the configuration on the storage backend
func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response,
	error) {
	if config, err := getConfig(ctx, req.Storage); err != nil {
		return nil, err
	} else {
		resp := &logical.Response{
			Data: map[string]interface{}{
				keyDefaultMaxTTL:           config.DefaultMaxTTL / time.Second,
				keyDefaultTTL:              config.DefaultTTL / time.Second,
				keyCACert:                  config.CACert,
				keyClientCert:              config.ClientCert,
				keyHost:                    config.Host,
				keyDefaultServiceAccountNs: config.DefaultServiceAccountNamespace,
			},
		}
		return resp, nil
	}
}

// pathConfigDelete removes the configuration on the storage backend
func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configPath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}

// getConfig is a helper function to simplify the loading
// of plugin configuration from the logical store
func getConfig(ctx context.Context, s logical.Storage) (*Config, error) {
	raw, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf(errorEmptyConfiguration)
	}
	conf := &Config{}
	_ = json.Unmarshal(raw.Value, conf)
	return conf, nil
}
