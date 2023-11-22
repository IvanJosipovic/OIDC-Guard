ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:0654dd034eecddddfae0cb136bdcdc26c6f6962edeb3b9b05bace06da4d82e2a AS build
WORKDIR /src
COPY oidc-guard.csproj .
RUN dotnet restore "oidc-guard.csproj"
COPY . .
RUN dotnet build "oidc-guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "oidc-guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-alpine@sha256:4e9ae5dabdf4177c83f572fb5d500e92aa4c000469806292af8e3cff36d0f472 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
LABEL org.opencontainers.image.description OpenID Connect (OIDC) Proxy Server for securing Kubernetes Ingress

# renovate: datasource=repology depName=alpine_3_18/ca-certificates-bundle
ENV CA-CERTIFICATES-BUNDLES_VERSION="20230506-r0"

# renovate: datasource=repology depName=alpine_3_18/libgcc
ENV LIBGCC_VERSION="12.2.1_git20220924-r10"

# renovate: datasource=repology depName=alpine_3_18/libssl3
ENV LIBSSL3_VERSION="3.1.4-r1"

# renovate: datasource=repology depName=alpine_3_18/libstdc++
ENV LIBSTDC_VERSION="12.2.1_git20220924-r10"

# renovate: datasource=repology depName=alpine_3_18/zlib
ENV ZLIB_VERSION="1.2.13-r1"

RUN apk update && \
    apk upgrade && \
    rm -rf /var/cache/apk/*

USER app

COPY --from=publish /app/publish .
ENTRYPOINT ["./oidc-guard"]
