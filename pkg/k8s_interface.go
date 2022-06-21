package secretsengine

import rbac "k8s.io/api/rbac/v1"

// KubernetesInterface defines the core functions for the Kubernetes integration
type KubernetesInterface interface {
	// CreateServiceAccount creates a new service account
	CreateServiceAccount(pluginConfig *Config, namespace string) (*ServiceAccount, error)

	// DeleteServiceAccount removes a services account
	DeleteServiceAccount(pluginConfig *Config, serviceAccount *ServiceAccount) error

	// CreateClusterRole creates a cluster role
	CreateClusterRole(pluginConfig *Config, rules []rbac.PolicyRule) (*ClusterRole, error)

	// DeleteClusterRole removes a cluster role
	DeleteClusterRole(pluginConfig *Config, clusterRole *ClusterRole) error

	// CreateRoleBinding creates a new rolebinding for a service account
	CreateRoleBinding(pluginConfig *Config, namespace string, clusterRole *ClusterRole, serviceAccount *ServiceAccount) (*RoleBinding, error)

	// DeleteRoleBinding removes an existing role binding
	DeleteRoleBinding(pluginConfig *Config, roleBinding *RoleBinding) error

	// CreateClusterRoleBinding creates a new clusterrolebinding for a service account
	CreateClusterRoleBinding(pluginConfig *Config, clusterRole *ClusterRole, serviceAccount *ServiceAccount) (*ClusterRoleBinding, error)

	// DeleteClusterRoleBinding removes an existing role binding
	DeleteClusterRoleBinding(pluginConfig *Config, clusterRoleBinding *ClusterRoleBinding) error
}

// ServiceAccount contains the details for a service account
type ServiceAccount struct {
	Namespace string                `json:"namespace"`
	Name      string                `json:"name"`
	Secret    *ServiceAccountSecret `json:"secret"`
}

// ServiceAccountSecret contain the details for a service account secret
type ServiceAccountSecret struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	CACert    string `json:"ca_cert"`
	Token     string `json:"-"`
}

// ClusterRole contains the details of a cluster role
type ClusterRole struct {
	Name string `json:"name"`
}

// ClusterRoleBinding contains the details of a cluster role binding
type ClusterRoleBinding struct {
	Name string `json:"name"`
}

// RoleBinding contains the details of a role binding
type RoleBinding struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}
