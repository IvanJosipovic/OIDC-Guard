![Logo](/docs/icon.png)

[![codecov](https://codecov.io/gh/IvanJosipovic/OIDC-Guard/branch/main/graph/badge.svg?token=M16OFqam3T)](https://codecov.io/gh/IvanJosipovic/OIDC-Guard)
[![GitHub](https://img.shields.io/github/stars/ivanjosipovic/oidc-guard?style=social)](https://github.com/IvanJosipovic/oidc-guard)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/oidc-guard)](https://artifacthub.io/packages/helm/oidc-guard/oidc-guard)
![Downloads](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fipitio%2Fbackage%2Frefs%2Fheads%2Findex%2FIvanJosipovic%2FOIDC-Guard%2Foidc-guard%25252Foidc-guard.json&query=%24.downloads&label=downloads)

OpenID Connect (OIDC) & OAuth 2 API Server used to secure Kubernetes Ingress

## What is this?

This project is an API server which is used along with Ingress Controllers that support External Authentication and enables per Ingress customizable JWT validation with Cookie support for Web Applications.

| Ingress Controller | JWT | Cookie|
|---|---|---|
| Nginx Ingress | X | X |
| Traefik | X | X |

## Features

- Per Ingress JWT Validation
  - A single instance of oidc-guard can protect a whole cluster with configurable rules per Ingress
- Cookie Auth for Web Applications
  - Returns an encrypted cookie which will be stored in the browser and sent on subsequent requests to pass through AuthN/AuthZ
- JWT Auth for APIs
  - Requests with a Bearer token in the Authorization header will be validated
  - Supports loading JSON Web Key Set (JWKS) from Url
  - Supports custom Authorization header
- AMD64 and ARM64 support

## Documentation

[Go to Wiki](https://github.com/IvanJosipovic/OIDC-Guard/wiki)
