package nodis

// KubernetesInterface defines the core functions for the Kubernetes integration
type KubernetesInterface interface {
	// CreateServiceAccount creates a new service account
	CreateServiceAccount(pluginConfig *PluginConfig, namespace string) (*ServiceAccountDetails, error)

	// GetServiceAccountSecret retrieves the secrets for a newly created service account
	GetServiceAccountSecret(pluginConfig *PluginConfig, sa *ServiceAccountDetails) ([]*ServiceAccountSecret, error)

	// DeleteServiceAccount removes a services account from the Kubernetes server
	DeleteServiceAccount(pluginConfig *PluginConfig, namespace string, serviceAccountName string) error

	// CreateRoleBinding creates a new rolebinding for a service account in a specific namespace
	CreateRoleBinding(pluginConfig *PluginConfig, namespace string, serviceAccountName string, roleName string) (*RoleBindingDetails, error)

	// CreateClusterRoleBinding creates a new rolebinding for a service account in a specific namespace
	CreateClusterRoleBinding(pluginConfig *PluginConfig, namespace string, serviceAccountName string, roleName string) (*ClusterRoleBindingDetails, error)

	// DeleteRoleBinding removes an existing role binding
	DeleteRoleBinding(pluginConfig *PluginConfig, namespace string, roleBindingName string) error

	// DeleteClusterRoleBinding removes an existing role binding
	DeleteClusterRoleBinding(pluginConfig *PluginConfig, clusterRoleBindingName string) error
}

// ServiceAccountDetails contains the details for a service account
type ServiceAccountDetails struct {
	Namespace string
	UID       string
	Name      string
}

// RoleBindingDetails contains the details of a RoleBinding
type RoleBindingDetails struct {
	Namespace string
	UID       string
	Name      string
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
