package secretsengine

import (
	"context"
	"fmt"
	"strconv"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/sony/sonyflake"
)

func pathRotateRootCredentials(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: rotateRootCredentialsPath,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.rotateRootCredentials,
			},
		},
		HelpSynopsis:    pathRotateCredentialsHelpSyn,
		HelpDescription: pathRotateCredentialsHelpDesc,
	}
}

func (b *backend) rotateRootCredentials(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	var expirationSeconds int32
	var certificate string

	pluginConfig, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if pluginConfig.Token != "" && pluginConfig.ClientCert == "" {
		return nil, fmt.Errorf("only certificates should be rotated")
	}

	clientCert, _ := parseCertificate(pluginConfig.ClientCert)
	crbs, _ := b.kubernetesService.GetSubjectClusterRoleBindings(ctx, pluginConfig, clientCert.Subject.CommonName)
	rbs, _ := b.kubernetesService.GetSubjectRoleBindings(ctx, pluginConfig, clientCert.Subject.CommonName)

	uniqueId, _ := sonyflake.NewSonyflake(sonyflake.Settings{}).NextID()
	subjectName := "vault-" + strconv.FormatUint(uniqueId, 16)
	subject := rbacv1.Subject{
		Kind: userKind,
		Name: subjectName,
	}
	key, csr := createKeyAndCertificateRequest(subjectName)
	if certificate, err = b.kubernetesService.SignCertificateRequest(ctx, pluginConfig, subjectName, csr, &expirationSeconds); err != nil {
		return nil, err
	}

	for _, crb := range crbs {
		_, err = b.kubernetesService.CreateClusterRoleBinding(ctx, pluginConfig, &crb.RoleRef, &subject)
		if err != nil {
			return nil, err
		}
	}
	for _, rb := range rbs {
		_, err = b.kubernetesService.CreateRoleBinding(ctx, pluginConfig, rb.Namespace, &rb.RoleRef, &subject)
		if err != nil {
			return nil, err
		}
	}

	newConfig := Config{
		Token:              pluginConfig.Token,
		ClientCert:         certificate,
		ClientKey:          encodeSecretKey(key),
		CACert:             pluginConfig.CACert,
		Host:               pluginConfig.Host,
		DefaultSANamespace: pluginConfig.DefaultSANamespace,
		DefaultTTL:         pluginConfig.DefaultTTL,
		DefaultMaxTTL:      pluginConfig.DefaultMaxTTL,
	}

	entry, _ := logical.StorageEntryJSON(configPath, newConfig)
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	pluginConfig, err = getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	for _, crb := range crbs {
		err = b.kubernetesService.DeleteClusterRoleBinding(ctx, pluginConfig, &crb)
		if err != nil {
			return nil, err
		}
	}
	for _, rb := range rbs {
		err = b.kubernetesService.DeleteRoleBinding(ctx, pluginConfig, &rb)
		if err != nil {
			return nil, err
		}
	}

	return &logical.Response{}, nil
}

const pathRotateCredentialsHelpSyn = `
Request to rotate the root credentials for a certain database connection.
`

const pathRotateCredentialsHelpDesc = `
This path attempts to rotate the root credentials for the given database. 
`

const pathRotateRoleCredentialsUpdateHelpSyn = `
Request to rotate the credentials for a static user account.
`

const pathRotateRoleCredentialsUpdateHelpDesc = `
This path attempts to rotate the credentials for the given static user account.
`
