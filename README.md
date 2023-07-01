# OIDC-Guard
[![codecov](https://codecov.io/gh/IvanJosipovic/OIDC-Guard/branch/main/graph/badge.svg?token=M16OFqam3T)](https://codecov.io/gh/IvanJosipovic/OIDC-Guard)
[![GitHub](https://img.shields.io/github/stars/ivanjosipovic/oidc-guard?style=social)](https://github.com/IvanJosipovic/oidc-guard)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/oidc-guard)](https://artifacthub.io/packages/helm/oidc-guard/oidc-guard)

OpenID Connect (OIDC) & OAuth 2 Proxy Server for securing Kubernetes Ingress

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

### Identity Provider Configuration

- Register an application with the following settings:
  - Reply Url: https://{hostname}/signin-oidc
  - Scopes: openid profile
  - Grant Type: Authorization Code
- Note down the ClientID and ClientSecret as they will be needed in the Helm Chart

### Configure Helm Values

Download the default [Helm Values](charts/oidc-guard/values.yaml)

```bash
curl https://raw.githubusercontent.com/IvanJosipovic/OIDC-Guard/main/charts/oidc-guard/values.yaml --output values.yaml
```

Modify the settings to fit your needs

### Install Helm Chart

```bash
helm repo add oidc-guard https://ivanjosipovic.github.io/OIDC-Guard

helm repo update

helm install oidc-guard oidc-guard/oidc-guard --create-namespace --namespace oidc-guard -f values.yaml
```

### Configure Ingress (external instance)

Use this approach if you configure oidc-guard with a dedicated ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress
  annotations:
    nginx.ingress.kubernetes.io/auth-url: https://oidc-guard.company.com/auth?tid=11111111-1111-1111-1111-111111111111&aud=22222222-2222-2222-2222-222222222222&aud=33333333-3333-3333-3333-333333333333
    nginx.ingress.kubernetes.io/auth-signin: https://oidc-guard.company.com/signin
spec:
```

### Parameters

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
    nginx.ingress.kubernetes.io/auth-url: https://oidc-guard.company.com/auth?aud=11111111-11111-1111111111&inject-claim=groups,JWT-Claim-Groups&inject-claim=scope,JWT-Claim-Scope
    nginx.ingress.kubernetes.io/auth-signin: https://oidc-guard.company.com/signin
    nginx.ingress.kubernetes.io/auth-response-headers: JWT-Claim-Groups, JWT-Claim-Scope
```

### Design

![alt text](https://raw.githubusercontent.com/IvanJosipovic/oidc-guard/main/docs/Workflow-Diagram.png)

### Metrics

Metrics are exposed on :8080/metrics

| Metric Name  | Description |
|---|---|
| oidc_guard_authorized | Number of Authorized operations ongoing |
| oidc_guard_unauthorized | Number of Unauthorized operations ongoing |
| oidc_guard_signin | Number of Sign-in operations ongoing |
