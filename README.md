# Kubernetes-webhook-token

This is a go implementation of a webhook-token service that alllows customization of authentication with the [kubernetes](https://kubernetes.io/docs/reference/access-authn-authz/webhook/). It talks to an AD server to authenticate users and return tokens that can be validated with kubernetes.
In future, I will implement this as an operator that will allow high customization of this service and can possible implement multiple data sources to validate users.
