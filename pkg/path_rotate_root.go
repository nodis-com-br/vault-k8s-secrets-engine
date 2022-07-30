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
	"fmt"
	client "k8s.io/client-go/kubernetes"

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
func (b *backend) pathRotateRootUpdate(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	var es int32
	var c string

	pluginConfig, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	clientSet, err := getClientset(ctx, pluginConfig)
	certClientSet, _ := getCertificatesV1Client(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}

	crbs, rbs, err := getSubjectBindings(ctx, b, clientSet, pluginConfig)
	if err != nil {
		return nil, err
	}

	nsn := resourceNamePrefix + getUniqueString(6)
	sbj := rbacv1.Subject{
		Kind: userKind,
		Name: nsn,
	}
	b.Logger().Info(fmt.Sprintf("creating credentials for %s", nsn))
	key, csr := createKeyAndCertificateRequest(nsn, defaultRSAKeyLength)
	if c, err = b.kubernetesService.SignCertificateRequest(ctx, certClientSet, nsn, csr, &es); err != nil {
		return nil, err
	}

	err = createBindingsForNewSubject(ctx, b, clientSet, sbj, crbs, rbs)
	if err != nil {
		return nil, err
	}

	newConfig := pluginConfig
	newConfig.ClientCert = c
	newConfig.ClientKey = key

	entry, _ := logical.StorageEntryJSON(configPath, newConfig)
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	pluginConfig, err = getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	err = deleteBindingsForOldSubject(ctx, b, clientSet, crbs, rbs)
	if err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func getSubjectBindings(ctx context.Context, b *backend, c client.Interface, p *Config) ([]rbacv1.ClusterRoleBinding,
	[]rbacv1.RoleBinding, error) {

	var n string

	if p.Token != "" {
		token, _ := jwt.Parse(p.Token, nil)
		n = token.Claims.(jwt.MapClaims)[tokenServiceAccountNameClaim].(string)
	} else {
		clientCert, _ := parseCertificate(p.ClientCert)
		n = clientCert.Subject.CommonName
	}

	crbs, _ := b.kubernetesService.GetSubjectClusterRoleBindings(ctx, c, n)
	rbs, _ := b.kubernetesService.GetSubjectRoleBindings(ctx, c, n)

	if len(crbs)+len(rbs) == 0 {
		return nil, nil, fmt.Errorf(errorNoBindingsForSubject)
	}
	return crbs, rbs, nil
}

func createBindingsForNewSubject(ctx context.Context, b *backend, c client.Interface, sbj rbacv1.Subject,
	crbs []rbacv1.ClusterRoleBinding, rbs []rbacv1.RoleBinding) error {
	for _, crb := range crbs {
		b.Logger().Info(fmt.Sprintf("creating cluster role binding to '%s' for '%s'", crb.RoleRef.Name,
			sbj.Name))
		_, err := b.kubernetesService.CreateClusterRoleBinding(ctx, c, &crb.RoleRef, &sbj)
		if err != nil {
			return err
		}
	}
	for _, rb := range rbs {
		b.Logger().Info(fmt.Sprintf("creating cluster role binding to '%s' for '%s'", rb.RoleRef.Name, sbj.Name))
		_, err := b.kubernetesService.CreateRoleBinding(ctx, c, rb.Namespace, &rb.RoleRef, &sbj)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteBindingsForOldSubject(ctx context.Context, b *backend, c client.Interface, crbs []rbacv1.ClusterRoleBinding,
	rbs []rbacv1.RoleBinding) error {
	for _, crb := range crbs {
		b.Logger().Info(fmt.Sprintf("deleting cluster role binding '%s'", crb.Name))
		err := b.kubernetesService.DeleteClusterRoleBinding(ctx, c, &crb)
		if err != nil {
			return err
		}
	}
	for _, rb := range rbs {
		b.Logger().Info(fmt.Sprintf("deleting role binding '%s'", rb.Name))
		err := b.kubernetesService.DeleteRoleBinding(ctx, c, &rb)
		if err != nil {
			return err
		}
	}
	return nil
}
