ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:1655c8f2784cf17f81191a9fd80fbf2e3f2ee1c2c86f174714635963986cb96b AS build
RUN apk add build-base zlib-dev
WORKDIR /src
COPY oidc-guard.csproj .
RUN dotnet restore "oidc-guard.csproj"
COPY . .
RUN dotnet build "oidc-guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "oidc-guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-alpine@sha256:f40ba3676c3dbbe013e03a765aab1c2dad7b72979412961dc81f086461759ce0 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
LABEL org.opencontainers.image.description OpenID Connect (OIDC) API Server for securing Kubernetes Ingress

# renovate: datasource=repology depName=alpine_3_18/ca-certificates-bundle versioning=loose
ENV CA-CERTIFICATES-BUNDLES_VERSION="20230506-r0"

# renovate: datasource=repology depName=alpine_3_18/libgcc versioning=loose
ENV LIBGCC_VERSION="12.2.1_git20220924-r10"

# renovate: datasource=repology depName=alpine_3_18/libssl3 versioning=loose
ENV LIBSSL3_VERSION="3.1.4-r1"

# renovate: datasource=repology depName=alpine_3_18/libstdc++ versioning=loose
ENV LIBSTDC_VERSION="12.2.1_git20220924-r10"

# renovate: datasource=repology depName=alpine_3_18/zlib versioning=loose
ENV ZLIB_VERSION="1.2.13-r1"

RUN apk update && \
    apk upgrade && \
    rm -rf /var/cache/apk/*

USER app

COPY --from=publish /app/publish .
ENTRYPOINT ["./oidc-guard"]
