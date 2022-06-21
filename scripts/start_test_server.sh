#!/usr/bin/env bash
set -e

REQUIRED_COMMANDS=(go vault kind kubectl)
for COMMAND in "${REQUIRED_COMMANDS[@]}"; do
  command -v "${COMMAND}" > /dev/null || (echo "${COMMAND} not found"; exit 1)
done

export VAULT_TOKEN=root
export VAULT_ADDR=http://127.0.0.1:8200

killall vault || true
kind create cluster 2> /dev/null || true

rm -rf dist/vault-k8s-secrets-engine
go build -o dist/vault-k8s-secrets-engine cmd/main.go
vault server -dev -dev-root-token-id="${VAULT_TOKEN}" -dev-plugin-dir=dist &
sleep 1
vault plugin register -sha256="$(sha256sum dist/vault-k8s-secrets-engine | cut -d ' ' -f1)"  -args="-tls-skip-verify" -command=vault-k8s-secrets-engine secret kubernetes
vault plugin info secret kubernetes
vault secrets enable kubernetes
kubectl config use kind-kind
kubectl apply -R -f manifests/

KIND_HOST=$(kind get kubeconfig | grep server | awk -F" " '{print $2}')
KIND_JWT=$(kubectl get secret vault-secrets-backend-secret -n kube-system -o jsonpath="{.data.token}" | base64 -d)
KIND_CA_CERT=$(kubectl get secret vault-secrets-backend-secret -n kube-system -o jsonpath="{.data.ca\.crt}" | base64 -d)

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
    "cluster_roles": ["admin"],
    "rules": [{"apiGroups": [""], "verbs":[ "get", "list"], "resources": ["secrets"]}]
  },
  {
    "namespaces": ["*"],
    "cluster_roles": ["view"]
  }
]
EOF
)

vault write kubernetes/config host="${KIND_HOST}" token="${KIND_JWT}" ca_cert="$KIND_CA_CERT"
vault read kubernetes/config
vault write kubernetes/role/admin binding_rules="${RULELIST01}"
vault read kubernetes/role/admin
vault write kubernetes/role/developer binding_rules="${RULELIST02}" view_nodes=true
vault read kubernetes/role/developer
vault list kubernetes/role


SECRET=$(vault read -format=json kubernetes/creds/developer ttl=5m)
#echo "${SECRET}" | jq -r 'del(.data.kube_config)'
echo "lease_duration: $(echo "${SECRET}" | jq -r .lease_duration)"
echo "${SECRET}" | jq -r .data.kube_config > kubeconfig


while true; do
  sleep 1
done

