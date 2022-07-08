package secretsengine

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	client "k8s.io/client-go/kubernetes"
	fakeClient "k8s.io/client-go/kubernetes/fake"
	certClient "k8s.io/client-go/kubernetes/typed/certificates/v1"
	fakeCertClient "k8s.io/client-go/kubernetes/typed/certificates/v1/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/testing"
)

// KubernetesService is an empty struct to wrap the Kubernetes service functions
type KubernetesService struct{}

// CreateServiceAccount creates a new serviceaccount with secret
func (k *KubernetesService) CreateServiceAccount(ctx context.Context, pluginConfig *Config, namespace string) (*corev1.ServiceAccount, *corev1.Secret, error) {

	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return nil, nil, err
	}

	serviceAccount, err := clientSet.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind: serviceAccountKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: resourceNamePrefix,
			Namespace:    namespace,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	serviceAccountSecret, err := clientSet.CoreV1().Secrets(serviceAccount.Namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccount.Name + tokenSecretNameSuffix,
			Namespace: serviceAccount.Namespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": serviceAccount.Name,
			},
		},
		Type: "kubernetes.io/service-account-token",
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	time.Sleep(sleepSeconds * time.Second)

	serviceAccountSecret, err = clientSet.CoreV1().Secrets(serviceAccountSecret.Namespace).Get(ctx, serviceAccountSecret.Name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	return serviceAccount, serviceAccountSecret, nil

}

// DeleteServiceAccount removes a serviceaccount and it's associated secrets
func (k *KubernetesService) DeleteServiceAccount(ctx context.Context, pluginConfig *Config, serviceAccount *corev1.ServiceAccount) error {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return err
	}
	if serviceAccount, err = clientSet.CoreV1().ServiceAccounts(serviceAccount.Namespace).Get(ctx, serviceAccount.Name, metav1.GetOptions{}); err != nil {
		if ctx.Value(keyTesting) != nil && ctx.Value(keyTesting).(bool) && err.(*errors.StatusError).Status().Code == 404 {
			serviceAccount = &corev1.ServiceAccount{Secrets: []corev1.ObjectReference{{}}}
		} else {
			return err
		}
	}
	for _, objRef := range serviceAccount.Secrets {
		if err = clientSet.CoreV1().Secrets(objRef.Namespace).Delete(ctx, objRef.Name, metav1.DeleteOptions{}); err != nil {
			if skipError404OnDelete(ctx, err) {
				return err
			}
		}
	}
	if err = clientSet.CoreV1().ServiceAccounts(serviceAccount.Namespace).Delete(ctx, serviceAccount.Name, metav1.DeleteOptions{}); err != nil {
		if skipError404OnDelete(ctx, err) {
			return err
		}
	}
	return nil
}

// SignCertificateRequest creates a CertificateSigningRequest, approve it and returns the signed certificate
func (k *KubernetesService) SignCertificateRequest(ctx context.Context, pluginConfig *Config, subjectName string, certificateSignRequest []byte, expirationSeconds *int32) (string, error) {

	clientSet, err := getCertificatesV1Client(ctx, pluginConfig)
	if err != nil {
		return "", err
	}

	csrTemplate := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: subjectName,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Usages:     []certificatesv1.KeyUsage{"client auth"},
			SignerName: "kubernetes.io/kube-apiserver-client",
			Groups: []string{
				"system:authenticated",
			},
			Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certificateSignRequest}),
		},
	}

	if *expirationSeconds > 0 {
		csrTemplate.Spec.ExpirationSeconds = expirationSeconds
	}

	csr, err := clientSet.CertificateSigningRequests().Create(ctx, csrTemplate, metav1.CreateOptions{})
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
	csr, err = clientSet.CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
	if err != nil {
		return "", err
	}

	time.Sleep(sleepSeconds * time.Second)

	csr, err = clientSet.CertificateSigningRequests().Get(ctx, csr.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if err = clientSet.CertificateSigningRequests().Delete(ctx, csr.Name, metav1.DeleteOptions{}); err != nil {
		return "", err
	}
	if len(csr.Status.Certificate) == 0 {
		if ctx.Value(keyTesting) != nil && ctx.Value(keyTesting).(bool) {
			csr.Status.Certificate = []byte("MOCK CERTIFICATE")
		} else {
			return "", fmt.Errorf("client certificate is empty")
		}
	}
	return base64.StdEncoding.EncodeToString(csr.Status.Certificate), nil
}

// CreateClusterRole creates a new clusterrole
func (k *KubernetesService) CreateClusterRole(ctx context.Context, pluginConfig *Config, rules []rbacv1.PolicyRule) (*rbacv1.ClusterRole, error) {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}
	return clientSet.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: resourceNamePrefix,
		},
		Rules: rules,
	}, metav1.CreateOptions{})
}

// DeleteClusterRole removes an existing clusterrole
func (k *KubernetesService) DeleteClusterRole(ctx context.Context, pluginConfig *Config, clusterRole *rbacv1.ClusterRole) error {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return err
	}
	if err = clientSet.RbacV1().ClusterRoles().Delete(ctx, clusterRole.Name, metav1.DeleteOptions{}); err != nil {
		if skipError404OnDelete(ctx, err) {
			return err
		}
	}
	return nil
}

// CreateRoleBinding creates a new rolebinding for a serviceaccount in a specific namespace
func (k *KubernetesService) CreateRoleBinding(ctx context.Context, pluginConfig *Config, namespace string, roleRef *rbacv1.RoleRef, subject *rbacv1.Subject) (*rbacv1.RoleBinding, error) {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}
	return clientSet.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: resourceNamePrefix,
			Namespace:    namespace,
		},
		Subjects: []rbacv1.Subject{*subject},
		RoleRef:  *roleRef,
	}, metav1.CreateOptions{})
}

// DeleteRoleBinding removes an existing rolebinding
func (k *KubernetesService) DeleteRoleBinding(ctx context.Context, pluginConfig *Config, roleBinding *rbacv1.RoleBinding) error {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return err
	}
	if err = clientSet.RbacV1().RoleBindings(roleBinding.Namespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{}); err != nil {
		if skipError404OnDelete(ctx, err) {
			return err
		}
	}
	return nil
}

// CreateClusterRoleBinding creates a new clusterrolebinding for a serviceaccount
func (k *KubernetesService) CreateClusterRoleBinding(ctx context.Context, pluginConfig *Config, roleRef *rbacv1.RoleRef, subject *rbacv1.Subject) (*rbacv1.ClusterRoleBinding, error) {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}
	return clientSet.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: resourceNamePrefix,
		},
		Subjects: []rbacv1.Subject{*subject},
		RoleRef:  *roleRef,
	}, metav1.CreateOptions{})
}

// DeleteClusterRoleBinding removes an existing clusterrolebinding
func (k *KubernetesService) DeleteClusterRoleBinding(ctx context.Context, pluginConfig *Config, clusterRoleBinding *rbacv1.ClusterRoleBinding) error {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return err
	}
	if err = clientSet.RbacV1().ClusterRoleBindings().Delete(ctx, clusterRoleBinding.Name, metav1.DeleteOptions{}); err != nil {
		if skipError404OnDelete(ctx, err) {
			return err
		}
	}
	return nil
}

func (k *KubernetesService) GetSubjectClusterRoleBindings(ctx context.Context, pluginConfig *Config, subjectName string) ([]rbacv1.ClusterRoleBinding, error) {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}
	crbList, _ := clientSet.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{
		FieldSelector: "subjects[0].name=" + subjectName,
	})
	if ctx.Value(keyTesting) != nil && ctx.Value(keyTesting).(bool) {
		return []rbacv1.ClusterRoleBinding{{}}, nil
	}
	return crbList.Items, nil
}

func (k *KubernetesService) GetSubjectRoleBindings(ctx context.Context, pluginConfig *Config, subjectName string) ([]rbacv1.RoleBinding, error) {
	clientSet, err := getClientset(ctx, pluginConfig)
	if err != nil {
		return nil, err
	}
	rbList, err := clientSet.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{
		FieldSelector: "subjects[0].name=" + subjectName,
	})
	if ctx.Value(keyTesting) != nil && ctx.Value(keyTesting).(bool) {
		return []rbacv1.RoleBinding{{}}, nil
	}
	return rbList.Items, err
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
	if ctx.Value(keyTesting) != nil && ctx.Value(keyTesting).(bool) {
		c := fakeClient.NewSimpleClientset()
		return c, nil
	} else {
		return client.NewForConfig(getRestConfig(pluginConfig))
	}
}

func getCertificatesV1Client(ctx context.Context, pluginConfig *Config) (certClient.CertificatesV1Interface, error) {
	if ctx.Value(keyTesting) != nil && ctx.Value(keyTesting).(bool) {
		return &fakeCertClient.FakeCertificatesV1{
			Fake: &testing.Fake{},
		}, nil
	} else {
		return certClient.NewForConfig(getRestConfig(pluginConfig))
	}
}

func skipError404OnDelete(ctx context.Context, err error) bool {
	if ctx.Value(keyTesting) != nil && !ctx.Value(keyTesting).(bool) && err.(*errors.StatusError).Status().Code != 404 {
		return true
	} else {
		return false
	}
}
