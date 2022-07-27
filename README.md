# Vault Kubernetes Secrets Engine

This project contains the source code for a [Hashicorp Vault](https://www.vaultproject.io/) plugin that provides on-demand short-lived [kubernetes](https://kubernetes.io/) client certificates or service account tokens. It was started as a fork from [servian/vault-k8s-secret-engine](https://github.com/servian/vault-k8s-secret-engine) and has since evolved into a fully fledged Vault backend engine with dynamic roles and root credentials rotation. Usage demonstration can be found on the [integration-test.sh](https://github.com/nodis-com-br/vault-k8s-secrets-engine/blob/master/integration-test.sh) script


## License

Permission to use, copy, modify, distribute, and sell this software and its 
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.  No representations are made about the suitability of this
software for any purpose.  It is provided "as is" without express or
implied warranty.