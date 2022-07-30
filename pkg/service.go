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
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

package secretsengine

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	"math/rand"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	client "k8s.io/client-go/kubernetes"
	fakeClient "k8s.io/client-go/kubernetes/fake"
	certClient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	fakeCertClient "k8s.io/client-go/kubernetes/typed/certificates/v1/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/testing"
)

var waitTime = defaultWaitTime * time.Second

// KubernetesService is an empty struct to wrap the Kubernetes service functions
type KubernetesService struct{}

// CreateServiceAccount creates a new service account with secret
func (k *KubernetesService) CreateServiceAccount(ctx context.Context, clientSet client.Interface,
	namespace string) (*corev1.ServiceAccount, *corev1.Secret, error) {

	sa, err := clientSet.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceNamePrefix + getUniqueString(4),
			Namespace: namespace,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	sas, err := clientSet.CoreV1().Secrets(sa.Namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sa.Name + tokenSecretNameSuffix,
			Namespace: sa.Namespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": sa.Name,
			},
		},
		Type: "kubernetes.io/service-account-token",
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	time.Sleep(waitTime)

	sas, err = clientSet.CoreV1().Secrets(sas.Namespace).Get(ctx, sas.Name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	return sa, sas, nil

}

// DeleteServiceAccount removes a service account and it's associated secrets
func (k *KubernetesService) DeleteServiceAccount(ctx context.Context, cs client.Interface,
	sa *corev1.ServiceAccount) error {
	sa, err := cs.CoreV1().ServiceAccounts(sa.Namespace).Get(ctx, sa.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	for _, objRef := range sa.Secrets {
		if err = cs.CoreV1().Secrets(objRef.Namespace).Delete(ctx, objRef.Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	return cs.CoreV1().ServiceAccounts(sa.Namespace).Delete(ctx, sa.Name, metav1.DeleteOptions{})
}

// SignCertificateRequest creates a certificate signing request,
// approves it and returns the signed certificate
func (k *KubernetesService) SignCertificateRequest(ctx context.Context, cs certClient.CertificatesV1Interface,
	sn string, csrBytes []byte, es *int32) (string, error) {

	csrTemplate := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: sn,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Usages:     []certificatesv1.KeyUsage{"client auth"},
			SignerName: "kubernetes.io/kube-apiserver-client",
			Groups:     []string{"system:authenticated"},
			Request:    []byte(pemEncode(csrBytes, "CERTIFICATE REQUEST")),
		},
	}

	if *es > 599 {
		csrTemplate.Spec.ExpirationSeconds = es
	}

	csr, err := cs.CertificateSigningRequests().Create(ctx, csrTemplate, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}

	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Status:         corev1.ConditionTrue,
		Type:           certificatesv1.CertificateApproved,
		Reason:         "Vault user activation",
		Message:        "This CSR was approved by the Vault secrets backend",
		LastUpdateTime: metav1.Now(),
	})
	csr, err = cs.CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
	if err != nil {
		return "", err
	}

	time.Sleep(waitTime)

	csr, err = cs.CertificateSigningRequests().Get(ctx, csr.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if err = cs.CertificateSigningRequests().Delete(ctx, csr.Name, metav1.DeleteOptions{}); err != nil {
		return "", err
	}
	if len(csr.Status.Certificate) == 0 {
		if fakeResponse(ctx) {
			_, cert := createKeyAndSelfSignedCertificate("test", testRSAKeyLength)
			csr.Status.Certificate = []byte(cert)
		} else {
			return "", fmt.Errorf(errorEmptyClientCertificate)
		}
	}
	return string(csr.Status.Certificate), nil
}

// CreateClusterRole creates a new cluster role
func (k *KubernetesService) CreateClusterRole(ctx context.Context, cs client.Interface,
	rs []rbacv1.PolicyRule) (*rbacv1.ClusterRole, error) {

	return cs.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: resourceNamePrefix + getUniqueString(4),
		},
		Rules: rs,
	}, metav1.CreateOptions{})
}

// DeleteClusterRole removes an existing cluster role
func (k *KubernetesService) DeleteClusterRole(ctx context.Context, cs client.Interface, cr *rbacv1.ClusterRole) error {
	return cs.RbacV1().ClusterRoles().Delete(ctx, cr.Name, metav1.DeleteOptions{})
}

// CreateRoleBinding creates a new role binding for a service account
func (k *KubernetesService) CreateRoleBinding(ctx context.Context, cs client.Interface, ns string, r *rbacv1.RoleRef,
	sbj *rbacv1.Subject) (*rbacv1.RoleBinding, error) {
	return cs.RbacV1().RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceNamePrefix + getUniqueString(4),
			Namespace: ns,
		},
		Subjects: []rbacv1.Subject{*sbj},
		RoleRef:  *r,
	}, metav1.CreateOptions{})
}

// DeleteRoleBinding removes an existing role binding
func (k *KubernetesService) DeleteRoleBinding(ctx context.Context, cs client.Interface, rb *rbacv1.RoleBinding) error {
	return cs.RbacV1().RoleBindings(rb.Namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{})
}

// CreateClusterRoleBinding creates a new cluster role binding for a service account
func (k *KubernetesService) CreateClusterRoleBinding(ctx context.Context, cs client.Interface, r *rbacv1.RoleRef,
	sbj *rbacv1.Subject) (*rbacv1.ClusterRoleBinding, error) {
	return cs.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: resourceNamePrefix + getUniqueString(4),
		},
		Subjects: []rbacv1.Subject{*sbj},
		RoleRef:  *r,
	}, metav1.CreateOptions{})
}

// DeleteClusterRoleBinding removes an existing cluster role binding
func (k *KubernetesService) DeleteClusterRoleBinding(ctx context.Context, cs client.Interface,
	crb *rbacv1.ClusterRoleBinding) error {
	return cs.RbacV1().ClusterRoleBindings().Delete(ctx, crb.Name, metav1.DeleteOptions{})
}

// GetSubjectClusterRoleBindings returns a list of the subject's cluster role bindings
func (k *KubernetesService) GetSubjectClusterRoleBindings(ctx context.Context, cs client.Interface,
	sbj string) ([]rbacv1.ClusterRoleBinding, error) {
	var result []rbacv1.ClusterRoleBinding
	crbList, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, crb := range crbList.Items {
		for _, subject := range crb.Subjects {
			if subject.Name == sbj {
				result = append(result, crb)
			}
		}
	}
	return result, nil
}

// GetSubjectRoleBindings returns a list of the subject's role bindings
func (k *KubernetesService) GetSubjectRoleBindings(ctx context.Context, cs client.Interface,
	sbj string) ([]rbacv1.RoleBinding, error) {
	var result []rbacv1.RoleBinding
	rbList, err := cs.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, rb := range rbList.Items {
		for _, subject := range rb.Subjects {
			if subject.Name == sbj {
				result = append(result, rb)
			}
		}
	}
	return result, err
}

func getRestConfig(pluginConfig *Config) *rest.Config {
	return &rest.Config{
		Host: pluginConfig.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData:   []byte(pluginConfig.CACert),
			CertData: []byte(pluginConfig.ClientCert),
			KeyData:  []byte(pluginConfig.ClientKey),
		},
		BearerToken: pluginConfig.Token,
	}
}

func getClientset(ctx context.Context, pluginConfig *Config) (client.Interface, error) {
	if ctx.Value(keyFakeK8sClient) != nil && ctx.Value(keyFakeK8sClient).(bool) {
		var objList []runtime.Object
		if ctx.Value(keyFakeK8sClientObjects) != nil {
			objList = ctx.Value(keyFakeK8sClientObjects).([]runtime.Object)
		}
		c := fakeClient.NewSimpleClientset(objList...)
		return c, nil
	} else {
		clientSet, err := client.NewForConfig(getRestConfig(pluginConfig))
		if err != nil {
			return nil, err
		}
		_, err = clientSet.ServerVersion()
		if err != nil {
			return nil, err
		}
		return clientSet, nil
	}
}

func getCertificatesV1Client(ctx context.Context, pluginConfig *Config) (certClient.CertificatesV1Interface, error) {
	if ctx.Value(keyFakeK8sClient) != nil && ctx.Value(keyFakeK8sClient).(bool) {
		return &fakeCertClient.FakeCertificatesV1{
			Fake: &testing.Fake{},
		}, nil
	} else {
		return certClient.NewForConfig(getRestConfig(pluginConfig))
	}
}

func fakeResponse(ctx context.Context) bool {
	if ctx.Value(keyFakeResponse) != nil {
		return ctx.Value(keyFakeResponse).(bool)
	} else {
		return false
	}
}

func getUniqueString(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
