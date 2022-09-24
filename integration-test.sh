#!/usr/bin/env bash
set -e

# Check for required tools for running the integrations test
REQUIRED_COMMANDS=(go vault kind kubectl docker jq)
for COMMAND in "${REQUIRED_COMMANDS[@]}"; do
  command -v "${COMMAND}" > /dev/null || (echo "${COMMAND} not found"; exit 1)
done

export VAULT_TOKEN=token
export VAULT_ADDR=http://127.0.0.1:8200

# Stop running vault server instances and start kind cluster
killall vault || true
kind create cluster || true

# Clean dist folder and build plugin
rm -rf dist/vault-k8s-secrets-engine
go build -o dist/vault-k8s-secrets-engine main.go

# Start vault server in development mode
vault server -dev -dev-root-token-id="${VAULT_TOKEN}" -dev-plugin-dir=dist &
sleep 1

# Register and enable plugin and print configuration
vault plugin register -sha256="$(sha256sum dist/vault-k8s-secrets-engine | cut -d ' ' -f1)"  -args="-tls-skip-verify" -command=vault-k8s-secrets-engine secret kubernetes
vault plugin info secret kubernetes
vault secrets enable kubernetes
kubectl config use kind-kind

# Reset kind cluster test resources
kubectl delete -R -f demo/ || true
kubectl apply -R -f demo/

# Extract plugin configuration from kind kubeconfig
KIND_HOST=$(kind get kubeconfig | grep server | awk -F" " '{print $2}')
KIND_CA_CERT=$(kind get kubeconfig | grep certificate-authority-data | awk -F" " '{print $2}' | base64 -d)

# Uncomment for certificate authentication on the root credentials
#KIND_CLIENT_CERT=$(kind get kubeconfig | grep client-certificate-data | awk -F" " '{print $2}' | base64 -d)
#KIND_CLIENT_KEY=$(kind get kubeconfig | grep client-key-data | awk -F" " '{print $2}' | base64 -d)
#vault write kubernetes/config host="${KIND_HOST}" ca_cert="$KIND_CA_CERT" client_cert="${KIND_CLIENT_CERT}" client_key="${KIND_CLIENT_KEY}"

# Uncomment for service account authentication on the root credentials
KIND_TOKEN=$(kubectl get secret vault-secrets-backend-secret -n kube-system -o jsonpath="{.data.token}" | base64 -d)
vault write kubernetes/config host="${KIND_HOST}" token="${KIND_TOKEN}" ca_cert="${KIND_CA_CERT}"

# Print plugin configuration
vault read kubernetes/config

# Rotate root credentials. It will replace token for client certificates
#vault write -force kubernetes/rotate-root

# Sample binding rules
BINDING_RULES01=$(cat <<EOF
[
  {
    "namespaces": ["*"],
    "cluster_roles": ["cluster-admin"]
  }
]
EOF
)

BINDING_RULES02=$(cat <<EOF
[
  {
    "namespaces": ["default"],
    "cluster_roles": ["cluster-admin"]
  },
  {
    "namespaces": ["*"],
    "cluster_roles": ["view"],
    "rules": [
      {"apiGroups": [""], "resources": ["events"], "verbs": ["create"]}
    ]
  }
]
EOF
)

# create sample roles
vault write kubernetes/role/admin binding_rules="${BINDING_RULES01}"
vault read kubernetes/role/admin
vault write kubernetes/role/developer binding_rules="${BINDING_RULES02}" list_namespaces=true view_nodes=true credentials_type=certificate
vault read kubernetes/role/developer
vault list kubernetes/role

# Generate credentials
vault read -format=json kubernetes/creds/developer ttl=5


while true; do
  sleep 1
done