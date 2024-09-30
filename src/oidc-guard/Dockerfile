ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:9.0-alpine@sha256:06735caeda36e5026cdd89e47700b3c9d70fd6b558f71f835b4f0d1d3f3581d8 AS build
RUN apk add build-base zlib-dev
WORKDIR /src
COPY oidc-guard.csproj .
RUN dotnet restore "oidc-guard.csproj"
COPY . .
RUN dotnet build "oidc-guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "oidc-guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:9.0-alpine@sha256:737dcd8ab926449aac55db5bae0e1d9e6b2ae789befed5cba492b5981e1ebc48 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
LABEL org.opencontainers.image.description OpenID Connect (OIDC) & OAuth 2 API Server used to secure Kubernetes Ingress

# renovate: datasource=repology depName=alpine_3_20/ca-certificates-bundle versioning=loose
ENV CA_CERTIFICATES_BUNDLES_VERSION="20240226-r0"

# renovate: datasource=repology depName=alpine_3_20/busybox versioning=loose
ENV BUSYBOX_VERSION="1.36.1-r19"

# renovate: datasource=repology depName=alpine_3_20/busybox-binsh versioning=loose
ENV BUSYBOX_BINSH_VERSION="1.36.1-r29"

# renovate: datasource=repology depName=alpine_3_20/libc-utils versioning=loose
ENV LIBC_UTILS_VERSION="0.7.2-r5"

# renovate: datasource=repology depName=alpine_3_20/libcrypto3 versioning=loose
ENV LIBCRYPTO3_VERSION="3.3.2-r0"

# renovate: datasource=repology depName=alpine_3_20/ssl_client versioning=loose
ENV SSL_VERSION="1.36.1-r29"

# renovate: datasource=repology depName=alpine_3_20/libgcc versioning=loose
ENV LIBGCC_VERSION="13.2.1_git20240309-r0"

# renovate: datasource=repology depName=alpine_3_20/libssl3 versioning=loose
ENV LIBSSL3_VERSION="3.3.2-r0"

# renovate: datasource=repology depName=alpine_3_20/libstdc++ versioning=loose
ENV LIBSTDC_VERSION="13.2.1_git20231014-r0"

RUN apk add --upgrade --no-cache \
        ca-certificates-bundle>$CA_CERTIFICATES_BUNDLES_VERSION \
        busybox>$BUSYBOX_BINSH_VERSION \
        busybox-binsh>$BUSYBOX_BINSH_VERSION \
        libc-utils>$LIBC_UTILS_VERSION \
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
