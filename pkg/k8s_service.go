package secretsengine

import (
	"time"

	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// KubernetesService is an empty struct to wrap the Kubernetes service functions
type KubernetesService struct{}

// CreateServiceAccount creates a new serviceaccount with secret
func (k *KubernetesService) CreateServiceAccount(pluginConfig *Config, namespace string) (*ServiceAccount, error) {

	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}

	serviceAccount, err := clientSet.CoreV1().ServiceAccounts(namespace).Create(&v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: defaultResourceNamePrefix,
			Namespace:    namespace,
		},
	})
	if err != nil {
		return nil, err
	}

	serviceAccountSecret, err := clientSet.CoreV1().Secrets(serviceAccount.Namespace).Create(&v1.Secret{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccount.Name + defaultTokenSecretNameSuffix,
			Namespace: serviceAccount.Namespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": serviceAccount.Name,
			},
		},
		Type: "kubernetes.io/service-account-token",
	})
	if err != nil {
		return nil, err
	}

	time.Sleep(1 * time.Second)

	serviceAccountSecret, err = clientSet.CoreV1().Secrets(serviceAccount.Namespace).Get(serviceAccountSecret.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return &ServiceAccount{
		Namespace: serviceAccount.Namespace,
		Name:      serviceAccount.Name,
		Secret: &ServiceAccountSecret{
			Namespace: serviceAccountSecret.Namespace,
			Name:      serviceAccountSecret.Name,
			CACert:    string(serviceAccountSecret.Data["ca.crt"]),
			Token:     string(serviceAccountSecret.Data["token"]),
		},
	}, nil

}

// DeleteServiceAccount removes a serviceaccount and it's associated secret
func (k *KubernetesService) DeleteServiceAccount(pluginConfig *Config, serviceAccount *ServiceAccount) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	if err = clientSet.CoreV1().Secrets(serviceAccount.Secret.Namespace).Delete(serviceAccount.Secret.Name, nil); err != nil {
		return err
	}
	if err = clientSet.CoreV1().ServiceAccounts(serviceAccount.Namespace).Delete(serviceAccount.Name, nil); err != nil {
		return err
	}
	return nil
}

// CreateClusterRole creates a new clusterrole
func (k *KubernetesService) CreateClusterRole(pluginConfig *Config, rules []rbac.PolicyRule) (*ClusterRole, error) {

	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}

	clusterRole, err := clientSet.RbacV1().ClusterRoles().Create(&rbac.ClusterRole{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: defaultResourceNamePrefix,
		},
		Rules: rules,
	})
	if err != nil {
		return nil, err
	}
	return &ClusterRole{
		Name: clusterRole.Name,
	}, nil

}

// DeleteClusterRole removes an existing clusterrole
func (k *KubernetesService) DeleteClusterRole(pluginConfig *Config, clusterRole *ClusterRole) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	if err = clientSet.RbacV1().ClusterRoles().Delete(clusterRole.Name, nil); err != nil {
		return err
	}
	return nil
}

// CreateRoleBinding creates a new rolebinding for a serviceaccount in a specific namespace
func (k *KubernetesService) CreateRoleBinding(pluginConfig *Config, namespace string, clusterRole *ClusterRole, serviceAccount *ServiceAccount) (*RoleBinding, error) {

	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}

	roleBinding, err := clientSet.RbacV1().RoleBindings(namespace).Create(&rbac.RoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: defaultResourceNamePrefix,
			Namespace:    namespace,
		},
		Subjects: []rbac.Subject{
			{
				Kind:      defaultServiceAccountKind,
				Name:      serviceAccount.Name,
				Namespace: serviceAccount.Namespace,
			},
		},
		RoleRef: rbac.RoleRef{
			Kind: defaultClusterRoleKind,
			Name: clusterRole.Name,
		},
	})
	if err != nil {
		return nil, err
	}

	return &RoleBinding{
		Namespace: roleBinding.Namespace,
		Name:      roleBinding.Name,
	}, nil

}

// DeleteRoleBinding removes an existing rolebinding
func (k *KubernetesService) DeleteRoleBinding(pluginConfig *Config, roleBinding *RoleBinding) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	if err = clientSet.RbacV1().RoleBindings(roleBinding.Namespace).Delete(roleBinding.Name, nil); err != nil {
		return err
	}
	return nil
}

// CreateClusterRoleBinding creates a new clusterrolebinding for a serviceaccount
func (k *KubernetesService) CreateClusterRoleBinding(pluginConfig *Config, clusterRole *ClusterRole, serviceAccount *ServiceAccount) (*ClusterRoleBinding, error) {

	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return nil, err
	}

	clusterRoleBinding, err := clientSet.RbacV1().ClusterRoleBindings().Create(&rbac.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: defaultResourceNamePrefix,
		},
		Subjects: []rbac.Subject{
			{
				Kind:      defaultServiceAccountKind,
				Name:      serviceAccount.Name,
				Namespace: serviceAccount.Namespace,
			},
		},
		RoleRef: rbac.RoleRef{
			Kind: defaultClusterRoleKind,
			Name: clusterRole.Name,
		},
	})
	if err != nil {
		return nil, err
	}

	return &ClusterRoleBinding{
		Name: clusterRoleBinding.Name,
	}, nil

}

// DeleteClusterRoleBinding removes an existing clusterrolebinding
func (k *KubernetesService) DeleteClusterRoleBinding(pluginConfig *Config, clusterRoleBinding *ClusterRoleBinding) error {
	clientSet, err := getClientSet(pluginConfig)
	if err != nil {
		return err
	}
	if err = clientSet.RbacV1().ClusterRoleBindings().Delete(clusterRoleBinding.Name, nil); err != nil {
		return err
	}
	return nil
}

// getClientSet sets up a new client for accessing the kubernetes API using a bearer token and a CACert
func getClientSet(pluginConfig *Config) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(&rest.Config{
		Host: pluginConfig.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: []byte(pluginConfig.CACert),
		},
		BearerToken: pluginConfig.Token,
	})

}
