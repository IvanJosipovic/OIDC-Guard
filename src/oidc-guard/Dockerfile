ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:17c6ca5fab0e9fb40ffa305ce6319c0812b84ad6488d99b2c682083c11778419 AS build
RUN apk add build-base zlib-dev
WORKDIR /src
COPY oidc-guard.csproj .
RUN dotnet restore "oidc-guard.csproj"
COPY . .
RUN dotnet build "oidc-guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "oidc-guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-alpine@sha256:a35eacfec6c14686b76d30f01bcfe05852b89673732e57d81a2c6fa3e4f91865 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
LABEL org.opencontainers.image.description OpenID Connect (OIDC) & OAuth 2 API Server used to secure Kubernetes Ingress

# renovate: datasource=repology depName=alpine_3_18/ca-certificates-bundle versioning=loose
ENV CA_CERTIFICATES_BUNDLES_VERSION="20240226-r0"

# renovate: datasource=repology depName=alpine_3_18/libgcc versioning=loose
ENV LIBGCC_VERSION="12.2.1_git20220924-r10"

# renovate: datasource=repology depName=alpine_3_18/libssl3 versioning=loose
ENV LIBSSL3_VERSION="3.1.5-r0"

# renovate: datasource=repology depName=alpine_3_18/libstdc++ versioning=loose
ENV LIBSTDC_VERSION="12.2.1_git20220924-r10"

# renovate: datasource=repology depName=alpine_3_18/zlib versioning=loose
ENV ZLIB_VERSION="1.2.13-r1"

RUN apk add --upgrade --no-cache \
        ca-certificates-bundle>$CA_CERTIFICATES_BUNDLES_VERSION \
        \
        # .NET dependencies
        libgcc>$LIBGCC_VERSION \
        libssl3>$LIBSSL3_VERSION \
        libstdc++>$LIBSTDC_VERSION \
        zlib>$ZLIB_VERSION

USER app

COPY --from=publish /app/publish .
ENTRYPOINT ["./oidc-guard"]
