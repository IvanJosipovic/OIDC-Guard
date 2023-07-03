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

## Documentation

[Go to Wiki](https://github.com/IvanJosipovic/OIDC-Guard/wiki)