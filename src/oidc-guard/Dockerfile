ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:9.0-alpine3.21@sha256:33be1326b4a2602d08e145cf7e4a8db4b243db3cac3bdec42e91aef930656080 AS build
RUN apk add build-base zlib-dev
WORKDIR /src
COPY oidc-guard.csproj .
RUN dotnet restore "oidc-guard.csproj"
COPY . .
RUN dotnet build "oidc-guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "oidc-guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:9.0-alpine3.21@sha256:77eda1f77b7a8d36d137a93ca6d32a2f948e63804993738a33f23dfb066ba15d AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
LABEL org.opencontainers.image.description="OpenID Connect (OIDC) & OAuth 2 API Server used to secure Kubernetes Ingress"

# renovate: datasource=repology depName=alpine_3_21/ca-certificates-bundle versioning=loose
ENV CA_CERTIFICATES_BUNDLES_VERSION="20241121-r1"

# renovate: datasource=repology depName=alpine_3_21/busybox versioning=loose
ENV BUSYBOX_VERSION="1.37.0-r12"

# renovate: datasource=repology depName=alpine_3_21/busybox-binsh versioning=loose
ENV BUSYBOX_BINSH_VERSION="1.37.0-r12"

# renovate: datasource=repology depName=alpine_3_21/libcrypto3 versioning=loose
ENV LIBCRYPTO3_VERSION="3.3.3-r0"

# renovate: datasource=repology depName=alpine_3_21/ssl_client versioning=loose
ENV SSL_VERSION="1.37.0-r12"

# renovate: datasource=repology depName=alpine_3_21/libgcc versioning=loose
ENV LIBGCC_VERSION="13.2.1_git20240309-r0"

# renovate: datasource=repology depName=alpine_3_21/libssl3 versioning=loose
ENV LIBSSL3_VERSION="3.3.3-r0"

# renovate: datasource=repology depName=alpine_3_21/libstdc++ versioning=loose
ENV LIBSTDC_VERSION="13.2.1_git20240309-r0"

RUN apk add --upgrade --no-cache \
        ca-certificates-bundle>$CA_CERTIFICATES_BUNDLES_VERSION \
        busybox>$BUSYBOX_BINSH_VERSION \
        busybox-binsh>$BUSYBOX_BINSH_VERSION \
        libcrypto3>$LIBCRYPTO3_VERSION \
        ssl_client>$SSL_VERSION \
        \
        # .NET dependencies
        libgcc>$LIBGCC_VERSION \
        libssl3>$LIBSSL3_VERSION \
        libstdc++>$LIBSTDC_VERSION

USER app

COPY --from=publish /app/publish .
ENTRYPOINT ["./oidc-guard"]
