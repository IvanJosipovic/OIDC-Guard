ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:39cc3baf22524c2cccf795c70afe14a49a38282f6d80a2264d23ff954f5bf693 AS build
RUN apk add build-base zlib-dev
WORKDIR /src
COPY oidc-guard.csproj .
RUN dotnet restore "oidc-guard.csproj"
COPY . .
RUN dotnet build "oidc-guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "oidc-guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-alpine@sha256:d6ee8dbe148acfd54c548550b905632a3adeef2d312b8f1cf5da57e785a03122 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
LABEL org.opencontainers.image.description OpenID Connect (OIDC) API Server for securing Kubernetes Ingress

# renovate: datasource=repology depName=alpine_3_18/ca-certificates-bundle versioning=loose
ENV CA_CERTIFICATES_BUNDLES_VERSION="20230506-r0"

# renovate: datasource=repology depName=alpine_3_18/libgcc versioning=loose
ENV LIBGCC_VERSION="12.2.1_git20220924-r10"

# renovate: datasource=repology depName=alpine_3_18/libssl3 versioning=loose
ENV LIBSSL3_VERSION="3.1.4-r5"

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
