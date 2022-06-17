package vault_k8s_secrets_engine

// KubernetesInterface defines the core functions for the Kubernetes integration
type KubernetesInterface interface {
	// CreateServiceAccount creates a new service account
	CreateServiceAccount(pluginConfig *PluginConfig, namespace string) (*ServiceAccountDetails, error)

	// CreateServiceAccountSecret retrieves the secrets for a newly created service account
	CreateServiceAccountSecret(pluginConfig *PluginConfig, sa *ServiceAccountDetails) (*ServiceAccountSecret, error)

	// DeleteServiceAccount removes a services account from the Kubernetes server
	DeleteServiceAccount(pluginConfig *PluginConfig, namespace string, serviceAccountName string) error

	// DeleteServiceAccountSecret removes a services account from the Kubernetes server
	DeleteServiceAccountSecret(pluginConfig *PluginConfig, namespace string, serviceAccountName string) error

	// CreateClusterRole creates a cluster role
	CreateClusterRole(pluginConfig *PluginConfig, rules string) (*ClusterRoleDetails, error)

	// DeleteClusterRole removes an existing cluster role
	DeleteClusterRole(pluginConfig *PluginConfig, clusterRoleName string) error

	// CreateClusterRoleBinding creates a new clusterrolebinding for a service account
	CreateClusterRoleBinding(pluginConfig *PluginConfig, namespace string, serviceAccountName string, roleName string) (*ClusterRoleBindingDetails, error)

	// DeleteClusterRoleBinding removes an existing role binding
	DeleteClusterRoleBinding(pluginConfig *PluginConfig, clusterRoleBindingName string) error

	// CreateRoleBinding creates a new rolebinding for a service account in a specific namespace
	CreateRoleBinding(pluginConfig *PluginConfig, serviceAccountName string, serviceAccountNamespace string, namespace string, roleName string) (*RoleBindingDetails, error)

	// DeleteRoleBinding removes an existing role binding
	DeleteRoleBinding(pluginConfig *PluginConfig, namespace string, roleBindingName string) error
}

// ServiceAccountDetails contains the details for a service account
type ServiceAccountDetails struct {
	Namespace string
	UID       string
	Name      string
}

// ClusterRoleDetails contains the details of a RoleBinding
type ClusterRoleDetails struct {
	UID  string
	Name string
}

// RoleBindingDetails contains the details of a RoleBinding
type RoleBindingDetails struct {
	Namespace string `json:"namespace"`
	UID       string
	Name      string `json:"name"`
}

// ClusterRoleBindingDetails contains the details of a RoleBinding
type ClusterRoleBindingDetails struct {
	UID  string
	Name string
}

// ServiceAccountSecret contain the secrets for a service account
type ServiceAccountSecret struct {
	CACert    string
	Namespace string
	Token     string
}
