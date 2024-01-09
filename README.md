# Kubernetes-webhook-token

This is a go implementation of a webhook-token service that alllows customization of authentication with the [kubernetes](https://kubernetes.io/docs/reference/access-authn-authz/webhook/). It talks to an AD server to authenticate users and return tokens that can be validated with kubernetes.
This can be extended to run as an operator that can configure the token service based on predefined configurations.
