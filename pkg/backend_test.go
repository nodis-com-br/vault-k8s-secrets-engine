package secretsengine

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	testSubject1         = "tester01"
	testSubject2         = "tester02"
	MaxTTL       float64 = 0
	TTL          float64 = 0
)

var (
	configs      []map[string]interface{}
	validRoles   []*TestEntity
	invalidRoles []*TestEntity
)

type TestEntity struct {
	Name  string
	Error string
	Value map[string]interface{}
}

func init() {

	waitTime = 0
	key1, cert1 := createKeyAndSelfSignedCertificate(testSubject1, testRSAKeyLength)
	_, cert2 := createKeyAndSelfSignedCertificate(testSubject2, testRSAKeyLength)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{tokenServiceAccountNameClaim: testSubject2})
	tokenString, _ := token.SignedString([]byte{})

	configs = []map[string]interface{}{
		{
			keyHost:          "https://localhost:443",
			keyCACert:        cert1,
			keyClientCert:    cert1,
			keyClientKey:     key1,
			keyDefaultMaxTTL: 0 * time.Second,
			keyDefaultTTL:    0 * time.Second,
		},
		{
			keyHost:          "https://127.0.0.1:443",
			keyCACert:        cert2,
			keyClientCert:    "",
			keyToken:         tokenString,
			keyDefaultTTL:    3600 * time.Second,
			keyDefaultMaxTTL: 7200 * time.Second,
		},
	}
	validRoles = []*TestEntity{
		{
			Name: "admin",
			Value: map[string]interface{}{
				keyBindingRules:     `[{"cluster_roles":["cluster-admin"],"namespaces":["*"],"rules":null}]`,
				keyListNamespaces:   defaultListNamespaces,
				keyViewNodes:        defaultViewNodes,
				keyCredentialsType:  defaultCredentialsType,
				keyServiceAccountNs: defaultServiceAccountNs,
				keyTTL:              TTL,
				keyMaxTTL:           MaxTTL,
			},
		},
		{
			Name: "developer",
			Value: map[string]interface{}{
				keyBindingRules:     `[{"cluster_roles":["cluster-admin"],"namespaces":["default"],"rules":null},{"cluster_roles":["view"],"namespaces":["*"],"rules":null}]`,
				keyListNamespaces:   true,
				keyViewNodes:        true,
				keyCredentialsType:  "token",
				keyServiceAccountNs: "",
				keyTTL:              TTL,
				keyMaxTTL:           MaxTTL,
			},
		},
	}
	invalidRoles = []*TestEntity{
		{
			Name: "empty_binding_rules",
			Value: map[string]interface{}{
				keyBindingRules: `[]`,
			},
			Error: errorEmptyBindingRules,
		},
		{
			Name: "invalid_json",
			Value: map[string]interface{}{
				keyBindingRules: `[{sunda: ["*"], "munga": ["cluster-admin"],}]`,
			},
			Error: "invalid character 's' looking for beginning of object key string",
		},
		{
			Name: "missing_rules_and_roles",
			Value: map[string]interface{}{
				keyBindingRules: `[{"namespaces": ["default"]}]`,
			},
			Error: errorMissingRulesAndRoles,
		},
		{
			Name: "empty_namespace_list",
			Value: map[string]interface{}{
				keyBindingRules: `[{}]`,
			},
			Error: errorEmptyNamespaceList,
		},
		{
			Name: "invalid_ttls",
			Value: map[string]interface{}{
				keyTTL:    1000,
				keyMaxTTL: 100,
			},
			Error: errorInvalidTTLs,
		},
	}
}

// getTestBackend constructs a test backend object.
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

func testStorageList(ctx context.Context, b logical.Backend, s logical.Storage, path string, expected []string) (*logical.Response, error) {
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
