# OIDC-Guard
[![codecov](https://codecov.io/gh/IvanJosipovic/OIDC-Guard/branch/alpha/graph/badge.svg?token=M16OFqam3T)](https://codecov.io/gh/IvanJosipovic/OIDC-Guard)
[![GitHub](https://img.shields.io/github/stars/ivanjosipovic/oidc-guard?style=social)](https://github.com/IvanJosipovic/oidc-guard)

OpenID Connect (OIDC) Proxy Server for securing Kubernetes Ingress

## What is this?

This project is an API server which is used along with the [nginx.ingress.kubernetes.io/auth-url](https://github.com/kubernetes/ingress-nginx/blob/main/docs/user-guide/nginx-configuration/annotations.md#external-authentication) annotation for ingress-nginx and enables per Ingress customizable JWT validation with Cookie support for Web Applications.

## Features

- Per Ingress JWT Validation
  - A single instance of oidc-guard can protect a whole cluster with configurable rules per Ingress
- Cookie Auth for Web Applications
  - Returns a cookie which will be stored in the browser and sent on subsequent requests to pass through AuthN/AuthZ
- JWT Auth for APIs
  - Requests with a Bearer token in the Authorization header will be validated
- AMD64 and ARM64 support

## Install

```bash
helm repo add oidc-guard https://ivanjosipovic.github.io/OIDC-Guard

helm repo update

helm install oidc-guard \
oidc-guard/oidc-guard \
--create-namespace \
--namespace oidc-guard \
--set settings.openIdProviderConfigurationUrl="https://login.microsoftonline.com/{guid}/v2.0/.well-known/openid-configuration" \
--set settings.cookieDomain="test.com" \
--set settings.clientId="my-client-id" \
--set settings.clientSecret="my-secret" \

```

## Options

- [Helm Values](charts/oidc-guard/values.yaml)

## Configure Ingress (external instance)

Use this approach if you configure oidc-guard with a dedicated ingress
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    nginx.ingress.kubernetes.io/auth-url: https://oidc-guard.company.com/auth?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222&aud=33333333-3333-3333-3333-333333333333
    nginx.ingress.kubernetes.io/auth-signin: https://oidc-guard.company.com/signin?rd=$scheme://$host$request_uri
spec:
```

## Parameters

The /auth endpoint supports configurable parameters in the format of \{claim\}=\{value\}. In the case the same claim is called more than once, the traffic will have to match only one.

For example, using the following query string
/auth?  
tid=11111111-1111-1111-1111-111111111111  
&aud=22222222-2222-2222-2222-222222222222  
&aud=33333333-3333-3333-3333-333333333333  

Along with validating the JWT token, the token must have a claim tid=11111111-1111-1111-1111-111111111111 and one of aud=22222222-2222-2222-2222-222222222222 or aud=33333333-3333-3333-3333-333333333333

### How to query arrays
The /auth endpoint is able to query arrays. We'll use the following JWT token in the example.
```json
{
  "email": "johndoe@example.com",
  "groups": ["admin", "developers"],
}
```

Using the following query string we can limit this endpoint to only tokens with an admin group
/auth?  
groups=admin

### Inject claims as headers
The /auth endpoint supports a custom parameter called "inject-claim". The value is the name of claim which will be added to the response headers.

For example, using the following query string
/auth?  
tid=11111111-1111-1111-1111-111111111111  
&aud=22222222-2222-2222-2222-222222222222  
&inject-claim=email

The /auth response will contain header email=someuser@domain.com

### Inject claims as headers with custom name
The value should be in the following format, "\{claim name\},\{header name\}".

For example, using the following query string
/auth?  
tid=11111111-1111-1111-1111-111111111111  
&aud=22222222-2222-2222-2222-222222222222  
&inject-claim=email,mail

The /auth response will contain header mail=someuser@domain.com

Example Ingress
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
  annotations:
    nginx.ingress.kubernetes.io/auth-url: https://oidc-guard.company.com/auth?aud=11111111-11111-1111111111&inject-claim=https%3A%2F%2Fexample.com%2Fgroups,groups&inject-claim=scope
    nginx.ingress.kubernetes.io/auth-signin: https://oidc-guard.company.com/signin?rd=$scheme://$host$request_uri
    nginx.ingress.kubernetes.io/configuration-snippet: |
      auth_request_set $groups $upstream_http_groups;
      auth_request_set $scope $upstream_http_scope;
      proxy_set_header JWT-Claim-Groups $groups;
      proxy_set_header JWT-Claim-Scope $scope;
```
