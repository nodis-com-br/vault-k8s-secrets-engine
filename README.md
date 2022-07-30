[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=coverage)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=bugs)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=nodis-com-br_vault-k8s-secrets-engine&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=nodis-com-br_vault-k8s-secrets-engine)
# Vault Kubernetes Secrets Engine

This project contains the source code for a [Hashicorp Vault](https://www.vaultproject.io/) plugin that provides on-demand short-lived [kubernetes](https://kubernetes.io/) client certificates or service account tokens. It was started as a fork from [servian/vault-k8s-secret-engine](https://github.com/servian/vault-k8s-secret-engine) and has since evolved into a fully fledged Vault backend engine with dynamic roles and root credentials rotation. Usage demonstration can be found on the [integration-test.sh](https://github.com/nodis-com-br/vault-k8s-secrets-engine/blob/master/integration-test.sh) script


## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details. <https://github.com/nodis-com-br/vault-k8s-secrets-engine/blob/master/lgpl-3.0.txt>.