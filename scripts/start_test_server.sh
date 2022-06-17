#!/usr/bin/env bash
set -e

export VAULT_TOKEN=root
export VAULT_ADDR=http://127.0.0.1:8200

killall vault || true
rm dist/vault-k8s-secrets-engine
/usr/local/go/bin/go build -o dist/vault-k8s-secrets-engine cmd/main.go
vault server -dev -dev-root-token-id="${VAULT_TOKEN}" -dev-plugin-dir=dist &
sleep 1
vault plugin register -sha256="$(sha256sum dist/vault-k8s-secrets-engine | cut -d ' ' -f1)"  -args="-tls-skip-verify" -command=vault-k8s-secrets-engine secret kubernetes
vault plugin info secret kubernetes
vault secrets enable kubernetes
kubectl config use kind-kind
kubectl apply -R -f manifests/
vault write kubernetes/config host="https://127.0.0.1:43693" jwt="$(kubectl get secret vault-secrets-backend-secret -n kube-system -o jsonpath="{.data.token}" | base64 -d)" ca_cert="$(kubectl get secret vault-secrets-backend-secret -n kube-system -o jsonpath="{.data.ca\.crt}")"
vault read kubernetes/config
vault write kubernetes/role/admin rules="[{\"verbs\": [\"*\"], \"apiGroups\": [\"*\"], \"resources\": [\"*\"]}]"
vault read kubernetes/role/admin
vault read -format=json kubernetes/creds/admin | jq -r .