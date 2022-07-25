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
func (k *KubernetesService) CreateServiceAccount(ctx context.Context, clientSet client.Interface, namespace string) (*corev1.ServiceAccount, *corev1.Secret, error) {

	serviceAccount, err := clientSet.CoreV1().ServiceAccounts(namespace).Create(ctx, &corev1.ServiceAccount{
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

	time.Sleep(waitTime)

	serviceAccountSecret, err = clientSet.CoreV1().Secrets(serviceAccountSecret.Namespace).Get(ctx, serviceAccountSecret.Name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	return serviceAccount, serviceAccountSecret, nil

}

// DeleteServiceAccount removes a service account and it's associated secrets
func (k *KubernetesService) DeleteServiceAccount(ctx context.Context, clientSet client.Interface, serviceAccount *corev1.ServiceAccount) error {
	serviceAccount, err := clientSet.CoreV1().ServiceAccounts(serviceAccount.Namespace).Get(ctx, serviceAccount.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	for _, objRef := range serviceAccount.Secrets {
		if err = clientSet.CoreV1().Secrets(objRef.Namespace).Delete(ctx, objRef.Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}
	return clientSet.CoreV1().ServiceAccounts(serviceAccount.Namespace).Delete(ctx, serviceAccount.Name, metav1.DeleteOptions{})
}

// SignCertificateRequest creates a certificate signing request,
// approves it and returns the signed certificate
func (k *KubernetesService) SignCertificateRequest(ctx context.Context, clientSet certClient.CertificatesV1Interface, subjectName string, csrBytes []byte, expirationSeconds *int32) (string, error) {

	csrTemplate := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: subjectName,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Usages:     []certificatesv1.KeyUsage{"client auth"},
			SignerName: "kubernetes.io/kube-apiserver-client",
			Groups:     []string{"system:authenticated"},
			Request:    []byte(pemEncode(csrBytes, "CERTIFICATE REQUEST")),
		},
	}

	if *expirationSeconds > 599 {
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

	time.Sleep(waitTime)

	csr, err = clientSet.CertificateSigningRequests().Get(ctx, csr.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if err = clientSet.CertificateSigningRequests().Delete(ctx, csr.Name, metav1.DeleteOptions{}); err != nil {
		return "", err
	}
	if len(csr.Status.Certificate) == 0 {
		if fakeResponse(ctx) {
			_, cert := createKeyAndSelfSignedCertificate("test", testRSAKeyLength)
			csr.Status.Certificate = []byte(cert)
		} else {
			return "", fmt.Errorf(emptyClientCertificate)
		}
	}
	return string(csr.Status.Certificate), nil
}

// CreateClusterRole creates a new cluster role
func (k *KubernetesService) CreateClusterRole(ctx context.Context, clientSet client.Interface, rules []rbacv1.PolicyRule) (*rbacv1.ClusterRole, error) {

	return clientSet.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: resourceNamePrefix + getUniqueString(4),
		},
		Rules: rules,
	}, metav1.CreateOptions{})
}

// DeleteClusterRole removes an existing cluster role
func (k *KubernetesService) DeleteClusterRole(ctx context.Context, clientSet client.Interface, clusterRole *rbacv1.ClusterRole) error {
	return clientSet.RbacV1().ClusterRoles().Delete(ctx, clusterRole.Name, metav1.DeleteOptions{})
}

// CreateRoleBinding creates a new role binding for a service account
func (k *KubernetesService) CreateRoleBinding(ctx context.Context, clientSet client.Interface, namespace string, roleRef *rbacv1.RoleRef, subject *rbacv1.Subject) (*rbacv1.RoleBinding, error) {
	return clientSet.RbacV1().RoleBindings(namespace).Create(ctx, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourceNamePrefix + getUniqueString(4),
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{*subject},
		RoleRef:  *roleRef,
	}, metav1.CreateOptions{})
}

// DeleteRoleBinding removes an existing role binding
func (k *KubernetesService) DeleteRoleBinding(ctx context.Context, clientSet client.Interface, roleBinding *rbacv1.RoleBinding) error {
	return clientSet.RbacV1().RoleBindings(roleBinding.Namespace).Delete(ctx, roleBinding.Name, metav1.DeleteOptions{})
}

// CreateClusterRoleBinding creates a new cluster role binding for a service account
func (k *KubernetesService) CreateClusterRoleBinding(ctx context.Context, clientSet client.Interface, roleRef *rbacv1.RoleRef, subject *rbacv1.Subject) (*rbacv1.ClusterRoleBinding, error) {
	return clientSet.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: resourceNamePrefix + getUniqueString(4),
		},
		Subjects: []rbacv1.Subject{*subject},
		RoleRef:  *roleRef,
	}, metav1.CreateOptions{})
}

// DeleteClusterRoleBinding removes an existing cluster role binding
func (k *KubernetesService) DeleteClusterRoleBinding(ctx context.Context, clientSet client.Interface, clusterRoleBinding *rbacv1.ClusterRoleBinding) error {
	return clientSet.RbacV1().ClusterRoleBindings().Delete(ctx, clusterRoleBinding.Name, metav1.DeleteOptions{})
}

// GetSubjectClusterRoleBindings returns a list of the subject's cluster role bindings
func (k *KubernetesService) GetSubjectClusterRoleBindings(ctx context.Context, clientSet client.Interface, subjectName string) ([]rbacv1.ClusterRoleBinding, error) {
	var result []rbacv1.ClusterRoleBinding
	crbList, err := clientSet.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, crb := range crbList.Items {
		for _, subject := range crb.Subjects {
			if subject.Name == subjectName {
				result = append(result, crb)
			}
		}
	}
	return result, nil
}

// GetSubjectRoleBindings returns a list of the subject's role bindings
func (k *KubernetesService) GetSubjectRoleBindings(ctx context.Context, clientSet client.Interface, subjectName string) ([]rbacv1.RoleBinding, error) {
	var result []rbacv1.RoleBinding
	rbList, err := clientSet.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, rb := range rbList.Items {
		for _, subject := range rb.Subjects {
			if subject.Name == subjectName {
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
