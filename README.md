[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=coverage)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=bugs)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
# Vault Kubernetes Secrets Engine

This project contains the source code for a [Hashicorp Vault](https://www.vaultproject.io/) plugin that provides on-demand short-lived [kubernetes](https://kubernetes.io/) client certificates or service account tokens. It was started as a fork from [servian/vault-k8s-secret-engine](https://github.com/servian/vault-k8s-secret-engine) and has since evolved into a fully fledged Vault backend engine with dynamic roles and root credentials rotation. Usage demonstration can be found on the [integration-test.sh](https://github.com/nodis-com-br/vault-k8s-secrets-engine/blob/master/integration-test.sh) script


## License

Permission to use, copy, modify, distribute, and sell this software and its documentation 
for any purpose is hereby granted without fee.  No representations are made about 
the suitability of this software for any purpose. It is provided "as is" without express or
implied warranty.