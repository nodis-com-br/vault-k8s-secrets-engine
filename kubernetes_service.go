package vault_k8s_secrets_engine

import (
	"encoding/json"
	"fmt"
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const serviceAccountNamePrefix = "vault-sa-"
const clusterRoleNamePrefix = "vault-cr-"
const roleBindingNamePrefix = "vault-rb-"
const clusterRoleBindingNamePrefix = "vault-crb-"

// KubernetesService is an empty struct to wrap the Kubernetes service functions
type KubernetesService struct{}

// CreateServiceAccount creates a new service account
func (k *KubernetesService) CreateServiceAccount(pluginConfig *PluginConfig, namespace string) (*ServiceAccountDetails, error) {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}
	sa := v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: serviceAccountNamePrefix,
			Namespace:    namespace,
		},
	}
	sar, err := clientSet.CoreV1().ServiceAccounts(namespace).Create(&sa)
	if err != nil {
		return nil, err
	}

	var secrets []*string
	for _, item := range sar.Secrets {
		s := item.String()
		secrets = append(secrets, &s)
	}

	return &ServiceAccountDetails{
		Namespace: sar.Namespace,
		UID:       fmt.Sprintf("%s", sar.UID),
		Name:      sar.Name,
	}, nil
}

// CreateServiceAccountSecret retrieves the secrets for a newly created service account
func (k *KubernetesService) CreateServiceAccountSecret(pluginConfig *PluginConfig, sa *ServiceAccountDetails) (*ServiceAccountSecret, error) {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}

	secretObj := v1.Secret{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: sa.Name + "-token",
			Namespace:    sa.Namespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": sa.Name,
			},
		},
		Type: "kubernetes.io/service-account-token",
	}
	secretCreated, err := clientSet.CoreV1().Secrets(sa.Namespace).Create(&secretObj)

	if err != nil {
		return nil, err
	}

	s := &ServiceAccountSecret{
		CACert:    string(secretCreated.Data["ca.crt"]),
		Namespace: string(secretCreated.Data["namespace"]),
		Token:     string(secretCreated.Data["token"]),
	}

	return s, nil
}

// DeleteServiceAccount removes a services account from the Kubernetes server
func (k *KubernetesService) DeleteServiceAccount(pluginConfig *PluginConfig, namespace string, serviceAccountName string) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	err = clientSet.CoreV1().ServiceAccounts(namespace).Delete(serviceAccountName, nil)
	if err != nil {
		return err
	}
	return nil
}

// DeleteServiceAccountSecret removes a services account from the Kubernetes server
func (k *KubernetesService) DeleteServiceAccountSecret(pluginConfig *PluginConfig, namespace string, serviceAccountName string) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	err = clientSet.CoreV1().Secrets(namespace).Delete(serviceAccountName+"-token", nil)
	if err != nil {
		return err
	}
	return nil
}

// CreateClusterRole creates a new cluster role
func (k *KubernetesService) CreateClusterRole(pluginConfig *PluginConfig, rules string) (*ClusterRoleDetails, error) {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}

	policyRules := make([]rbac.PolicyRule, 0)
	_ = json.Unmarshal([]byte(rules), &policyRules)

	cr := rbac.ClusterRole{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: clusterRoleNamePrefix,
		},
		Rules: policyRules,
	}
	crr, err := clientSet.RbacV1().ClusterRoles().Create(&cr)
	if err != nil {
		return nil, err
	}
	return &ClusterRoleDetails{
		UID:  fmt.Sprintf("%s", crr.UID),
		Name: crr.Name,
	}, nil
}

// DeleteClusterRole removes an existing cluster role
func (k *KubernetesService) DeleteClusterRole(pluginConfig *PluginConfig, clusterRoleName string) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	err = clientSet.RbacV1().ClusterRoles().Delete(clusterRoleName, nil)
	if err != nil {
		return err
	}
	return nil
}

// CreateRoleBinding creates a new rolebinding for a service account in a specific namespace
func (k *KubernetesService) CreateRoleBinding(pluginConfig *PluginConfig, serviceAccountName string, serviceAccountNamespace string, namespace string, clusterRoleName string) (*RoleBindingDetails, error) {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}

	subjects := []rbac.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      serviceAccountName,
			Namespace: serviceAccountNamespace,
		},
	}

	roleBinding := rbac.RoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: roleBindingNamePrefix,
			Namespace:    namespace,
		},
		Subjects: subjects,
		RoleRef: rbac.RoleRef{
			Kind: "ClusterRole",
			Name: clusterRoleName,
		},
	}

	rb, err := clientSet.RbacV1().RoleBindings(namespace).Create(&roleBinding)
	if err != nil {
		return nil, err
	}
	return &RoleBindingDetails{
		Namespace: rb.Namespace,
		UID:       fmt.Sprintf("%s", rb.UID),
		Name:      rb.Name,
	}, nil
}

// CreateClusterRoleBinding creates a new clusterrolebinding for a service account
func (k *KubernetesService) CreateClusterRoleBinding(pluginConfig *PluginConfig, serviceAccountNamespace string, serviceAccountName string, clusterRoleName string) (*ClusterRoleBindingDetails, error) {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}
	subjects := []rbac.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      serviceAccountName,
			Namespace: serviceAccountNamespace,
		},
	}

	clusterRoleBinding := rbac.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: clusterRoleBindingNamePrefix,
		},
		Subjects: subjects,
		RoleRef: rbac.RoleRef{
			Kind: "ClusterRole",
			Name: clusterRoleName,
		},
	}

	rb, err := clientSet.RbacV1().ClusterRoleBindings().Create(&clusterRoleBinding)
	if err != nil {
		return nil, err
	}
	return &ClusterRoleBindingDetails{
		UID:  fmt.Sprintf("%s", rb.UID),
		Name: rb.Name,
	}, nil
}

// DeleteRoleBinding removes an existing role binding
func (k *KubernetesService) DeleteRoleBinding(pluginConfig *PluginConfig, namespace string, roleBindingName string) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	err = clientSet.RbacV1().RoleBindings(namespace).Delete(roleBindingName, nil)
	if err != nil {
		return err
	}
	return nil
}

// DeleteClusterRoleBinding removes an existing cluster role binding
func (k *KubernetesService) DeleteClusterRoleBinding(pluginConfig *PluginConfig, clusterRoleBindingName string) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	err = clientSet.RbacV1().ClusterRoleBindings().Delete(clusterRoleBindingName, nil)
	if err != nil {
		return err
	}
	return nil
}

// getClientSet sets up a new client for accessing the kubernetes API using a bearer token and a CACert
func getClientSet(pluginConfig *PluginConfig) (*kubernetes.Clientset, error) {

	tlsConfig := rest.TLSClientConfig{
		Insecure: true,
		//CAData:   []byte(pluginConfig.CACert),
	}

	conf := &rest.Config{
		Host:            pluginConfig.Host,
		TLSClientConfig: tlsConfig,
		BearerToken:     pluginConfig.ServiceAccountJWT,
	}

	return kubernetes.NewForConfig(conf)
}
