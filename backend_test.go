package secretsengine

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	MaxTTL     float64 = 0
	TTL        float64 = 0
	clientCert         = `-----BEGIN CERTIFICATE-----
MIIEBTCCAu2gAwIBAgIQTtDhuauerZQT+FcG2Q1jjzANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDEwprdWJlcm5ldGVzMB4XDTIyMDcwOTE5MTE1M1oXDTIyMDcwOTE5
MjY1M1owIDEeMBwGA1UEAxMVdG9rZW4tNWM1NjM2MjFkMDAwMTEwMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz09ClfxJCI2F2xHS4CDvr3CXwnOHDVej
JfiPTAbDcprngUlkqAavDUfotj0xsEpX1keS77tM2GzEeEYnfF/DvfQp4IdV36p3
o7fLu1M2EPHej7dxmfKzvFidCk7DloCFCsq27WMcu3A/i0Mr6h+/AeAiBMv/Wiqq
HGieMLZvkQot2L+g2IErht9I6nNljSEpnOs05Pzxhc94PCP5UUpD8wjmt9bnvMcU
mnSmNJrMFeil1Ak8NSoFwYGEnxaiTkgdi9C2et6dW5bijegm7Dc8FJ38F6GTt6aO
IZ0jWSYqAAeuIhbBSf3iKdNK0hRKltJHkXSI7TduF6x4Qe9iDZ8vCZaodyf33Jtk
so/MsIlMgofE9zlGCMfNAGJuXdbAToJa7lH181FtIZ52QYEVR5quqEMaND6kuy/w
zqew6U7aoLzLuwXO8aacv0KEBsxSUOtqhW/rB6t6vx/1bb1maOlGjqXHKlhxkpCP
+iDNS2PqVjbPvC5mxRMDOnpFG2FuuQOg5Xk22XhzuiJUIzl+s8Xx7CZ9rIE4Npco
GddPR3wYqBOYMg59h+3ySi9AS5bCyOzpQDFJsuAvbSpfmPj3wrG4e22OVTZ3j6s7
TZoQmNhi+CqgiDP2KLChE1nU9wMend8rbaUyzaHL6DelXp8MjxUm7h1pFk8GYnQk
j1o1/NEOm9kCAwEAAaNGMEQwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/
BAIwADAfBgNVHSMEGDAWgBSM/wrvXNS51zKl0BC/DoJOHyvCgTANBgkqhkiG9w0B
AQsFAAOCAQEAG2Prjx3K/JfgqWori2L3SEGROINd3Wsk/WDDO1H7sqgC0oAWrqEh
3hTfnj1Zp2v/gM3MYmncWW4yKe5t+Er9yLdEDALGHaiRSja03LwdWIsoTfyOcISn
HabvTFh+R8jrrSI0BMGdpiYhRyeAxqFngw9eab6qgTonweP06mLx1krAmttpLqIy
OQWhH8Ffn9l0MDMIrMUV6+DxOp01j25K8oX9ONo/KI27d8/qZPz1w/YAzJrZvQgM
P0STdhu2G+8WDiwVbHbMPLv6ap8jalsw92CA6rMvV//Ih+RCXmSsoIn8pHbXrxyX
hf0eYHKrscPxBbB4HQDkdPT4Y4fL7sDQDA==
-----END CERTIFICATE-----`
	clientKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
)

var (
	configs = []map[string]interface{}{
		{
			keyHost:          "https://localhost:443",
			keyCACert:        clientCert,
			keyClientCert:    clientCert,
			keyClientKey:     clientKey,
			keyDefaultMaxTTL: 0 / time.Second,
			keyDefaultTTL:    0 / time.Second,
		},
		{
			keyHost:          "https://127.0.0.1:443",
			keyCACert:        "NEW CA CERTIFICATE",
			keyClientCert:    "",
			keyToken:         "TOKEN",
			keyDefaultTTL:    3600 / time.Second,
			keyDefaultMaxTTL: 7200 / time.Second,
		},
	}
	validRoles = []map[string]interface{}{
		{
			keyVaultRoleName:    "admin",
			keyBindingRules:     `[{"namespaces":["*"],"cluster_roles":["cluster-admin"],"rules":null}]`,
			keyListNamespaces:   defaultListNamespaces,
			keyViewNodes:        defaultViewNodes,
			keyCredentialsType:  defaultCredentialsType,
			keyServiceAccountNs: defaultServiceAccountNs,
			keyTTL:              TTL,
			keyMaxTTL:           MaxTTL,
		},
		{
			keyVaultRoleName:    "developer",
			keyBindingRules:     `[{"namespaces":["default"],"cluster_roles":["cluster-admin"],"rules":null},{"namespaces":["*"],"cluster_roles":["view"],"rules":null}]`,
			keyListNamespaces:   true,
			keyViewNodes:        true,
			keyCredentialsType:  "token",
			keyServiceAccountNs: "kube-system",
			keyTTL:              TTL,
			keyMaxTTL:           MaxTTL,
		},
	}
	invalidRoles = []map[string]interface{}{
		{
			keyVaultRoleName: "empty_bindingrules",
			keyBindingRules:  `[]`,
		},
		{
			keyVaultRoleName: "invalid_bindingrules_json",
			keyBindingRules:  `[{sunda: ["*"], "munga": ["cluster-admin"],}]`,
		},
		{
			keyVaultRoleName: "invalid_bindingrules_no_rules",
			keyBindingRules:  `[{"namespaces": ["default"]}]`,
		},
		{
			keyVaultRoleName: "empty_bindingrules_no_namespaces",
			keyBindingRules:  `[{}]`,
		},
		{
			keyVaultRoleName: "invalid_ttl",
			keyTTL:           1000,
			keyMaxTTL:        100,
		},
		{
			keyVaultRoleName:   "invalid_certificate_ttl",
			keyCredentialsType: "certificate",
			keyMaxTTL:          300,
		},
	}
)

// getTestBackend will help you construct a test backend object.
// Update this function with your target backend.
func getTestBackend(tb testing.TB) (*backend, logical.Storage, context.Context) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, keyTesting, true)

	return b.(*backend), config.StorageView, ctx
}

func testStorageCreate(ctx context.Context, b logical.Backend, s logical.Storage, path string, d map[string]interface{}) (*logical.Response, error) {
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      path,
		Data:      d,
		Storage:   s,
	})
	return resp, err
}

func testStorageRead(ctx context.Context, b logical.Backend, s logical.Storage, path string, d map[string]interface{}, expected map[string]interface{}) (*logical.Response, error) {
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Data:      d,
		Storage:   s,
	})
	if expected != nil {
		if len(expected) != len(resp.Data) {
			return resp, fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
		}
		for k, expectedV := range expected {
			actualV, ok := resp.Data[k]
			if !ok {
				return resp, fmt.Errorf(`expected data["%s"] = %v but was not included in read output`, k, expectedV)
			} else if expectedV != actualV {
				return resp, fmt.Errorf(`expected data["%s"] = %v [%T], instead got %v [%T]`, k, expectedV, expectedV, actualV, actualV)
			}
		}
	}
	return resp, err
}

func testStorageList(ctx context.Context, b *backend, s logical.Storage, path string, expected []string) (*logical.Response, error) {
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      path,
		Storage:   s,
	})
	if expected != nil {
		actual := resp.Data["keys"].([]string)
		if !reflect.DeepEqual(actual, expected) {
			return resp, fmt.Errorf("list mismatch: expected %v, actual %v)", expected, actual)
		}

	}
	return resp, err
}

func testStorageUpdate(ctx context.Context, b logical.Backend, s logical.Storage, path string, d map[string]interface{}) (*logical.Response, error) {
	return b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Data:      d,
		Storage:   s,
	})
}

func testStorageDelete(ctx context.Context, b logical.Backend, s logical.Storage, path string) (*logical.Response, error) {
	return b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      path,
		Storage:   s,
	})
}
