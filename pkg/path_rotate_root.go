/*
 * Vault Kubernetes Secrets Engine is a plugin for
 * generating dynamic kubernetes credentials with
 * Hashicorp Vault
 *
 * Contact: pedro.tonini@hotmail.com
 *
 * Vault Kubernetes Secrets Engine is free software; you can
 * redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Vault Kubernetes Secrets Engine is distributed in the hope that
 * it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 */

package secretsengine

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/golang-jwt/jwt/v4"
)

func pathRotateRootCredentials(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: rotateRootPath,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRotateRootUpdate,
			},
		},
		HelpSynopsis:    pathRotateRootHelpSyn,
		HelpDescription: pathRotateRootHelpDesc,
	}
}

// pathRotateRootUpdate creates and signs a new user certificate,
// copies all bindings from the current identity to the new and
// removes the original bindings. It DOES NOT remove the original
// identity itself.
func (b *backend) pathRotateRootUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	var expirationSeconds int32
	var certificate string
	var currentSubjectName string

	pluginConfig, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	clientSet, err := getClientset(ctx, pluginConfig)
	certClientSet, _ := getCertificatesV1Client(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}

	if pluginConfig.Token != "" {
		token, _ := jwt.Parse(pluginConfig.Token, nil)
		currentSubjectName = token.Claims.(jwt.MapClaims)[tokenServiceAccountNameClaim].(string)
	} else {
		clientCert, _ := parseCertificate(pluginConfig.ClientCert)
		currentSubjectName = clientCert.Subject.CommonName
	}

	crbs, _ := b.kubernetesService.GetSubjectClusterRoleBindings(ctx, clientSet, currentSubjectName)
	rbs, _ := b.kubernetesService.GetSubjectRoleBindings(ctx, clientSet, currentSubjectName)

	if len(crbs)+len(rbs) == 0 {
		return nil, fmt.Errorf(noBindingsForSubject)
	}

	newSubjectName := resourceNamePrefix + getUniqueString(6)
	subject := rbacv1.Subject{
		Kind: userKind,
		Name: newSubjectName,
	}
	b.Logger().Info(fmt.Sprintf("creating credentials for %s", newSubjectName))
	key, csr := createKeyAndCertificateRequest(newSubjectName, defaultRSAKeyLength)
	if certificate, err = b.kubernetesService.SignCertificateRequest(ctx, certClientSet, newSubjectName, csr, &expirationSeconds); err != nil {
		return nil, err
	}

	for _, crb := range crbs {
		b.Logger().Info(fmt.Sprintf("creating cluster role binding to '%s' for '%s'", crb.RoleRef.Name, subject.Name))
		_, err = b.kubernetesService.CreateClusterRoleBinding(ctx, clientSet, &crb.RoleRef, &subject)
		if err != nil {
			return nil, err
		}
	}
	for _, rb := range rbs {
		b.Logger().Info(fmt.Sprintf("creating cluster role binding to '%s' for '%s'", rb.RoleRef.Name, subject.Name))
		_, err = b.kubernetesService.CreateRoleBinding(ctx, clientSet, rb.Namespace, &rb.RoleRef, &subject)
		if err != nil {
			return nil, err
		}
	}

	//newConfig := &Config{
	//	ClientCert:                     certificate,
	//	ClientKey:                      key,
	//	CACert:                         pluginConfig.CACert,
	//	Host:                           pluginConfig.Host,
	//	DefaultServiceAccountNamespace: pluginConfig.DefaultServiceAccountNamespace,
	//	DefaultTTL:                     pluginConfig.DefaultTTL,
	//	DefaultMaxTTL:                  pluginConfig.DefaultMaxTTL,
	//}

	newConfig := pluginConfig
	newConfig.ClientCert = certificate
	newConfig.ClientKey = key

	entry, _ := logical.StorageEntryJSON(configPath, newConfig)
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	pluginConfig, err = getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	for _, crb := range crbs {
		b.Logger().Info(fmt.Sprintf("deleting cluster role binding '%s'", crb.Name))
		err = b.kubernetesService.DeleteClusterRoleBinding(ctx, clientSet, &crb)
		if err != nil {
			return nil, err
		}
	}
	for _, rb := range rbs {
		b.Logger().Info(fmt.Sprintf("deleting role binding '%s'", rb.Name))
		err = b.kubernetesService.DeleteRoleBinding(ctx, clientSet, &rb)
		if err != nil {
			return nil, err
		}
	}
	return &logical.Response{}, nil
}
