#!/usr/bin/env bash
set -e

REQUIRED_COMMANDS=(go vault kind kubectl docker jq)
for COMMAND in "${REQUIRED_COMMANDS[@]}"; do
  command -v "${COMMAND}" > /dev/null || (echo "${COMMAND} not found"; exit 1)
done

export VAULT_TOKEN=root
export VAULT_ADDR=http://127.0.0.1:8200

killall vault || true
kind create cluster || true

rm -rf dist/vault-k8s-secrets-engine
go build -o dist/vault-k8s-secrets-engine cmd/vault-k8s-secrets-engine/main.go
vault server -dev -dev-root-token-id="${VAULT_TOKEN}" -dev-plugin-dir=dist &
sleep 1
vault plugin register -sha256="$(sha256sum dist/vault-k8s-secrets-engine | cut -d ' ' -f1)"  -args="-tls-skip-verify" -command=vault-k8s-secrets-engine secret kubernetes
vault plugin info secret kubernetes
vault secrets enable kubernetes
kubectl config use kind-kind
kubectl delete -R -f manifests/ || true
kubectl apply -R -f manifests/

KIND_HOST=$(kind get kubeconfig | grep server | awk -F" " '{print $2}')
KIND_CA_CERT=$(kind get kubeconfig | grep certificate-authority-data | awk -F" " '{print $2}' | base64 -d)

#KIND_CLIENT_CERT=$(kind get kubeconfig | grep client-certificate-data | awk -F" " '{print $2}' | base64 -d)
#KIND_CLIENT_KEY=$(kind get kubeconfig | grep client-key-data | awk -F" " '{print $2}' | base64 -d)
#vault write kubernetes/config host="${KIND_HOST}" ca_cert="$KIND_CA_CERT" client_cert="${KIND_CLIENT_CERT}" client_key="${KIND_CLIENT_KEY}"

KIND_TOKEN=$(kubectl get secret vault-secrets-backend-secret -n kube-system -o jsonpath="{.data.token}" | base64 -d)
vault write kubernetes/config host="${KIND_HOST}" token="${KIND_TOKEN}" ca_cert="${KIND_CA_CERT}"

vault read kubernetes/config

vault write -force kubernetes/rotate-root

RULELIST01=$(cat <<EOF
[
  {
    "namespaces": ["*"],
    "cluster_roles": ["cluster-admin"]
  }
]
EOF
)

RULELIST02=$(cat <<EOF
[
  {
    "namespaces": ["default"],
    "cluster_roles": ["cluster-admin"]
  },
  {
    "namespaces": ["*"],
    "cluster_roles": ["view"]
  }
]
EOF
)

vault write kubernetes/role/admin binding_rules="${RULELIST01}"
vault read kubernetes/role/admin
vault write kubernetes/role/developer binding_rules="${RULELIST02}" view_nodes=true credentials_type=certificate
vault read kubernetes/role/developer
vault list kubernetes/role

SECRET=$(vault read -format=json kubernetes/creds/developer ttl=5)
#echo "${SECRET}" | jq -r 'del(.data)'
#echo "${SECRET}" | jq -r .data.user_cert | base64 -d | openssl x509 -text
#echo "${SECRET}" | jq -r .data.kube_config > kubeconfig
#

while true; do
  sleep 1
done