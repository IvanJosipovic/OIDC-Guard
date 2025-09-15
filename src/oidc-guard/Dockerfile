ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/aspnet:10.0-alpine3.22@sha256:2a325357e7315a0ea014931e3b89d6feeba56d692c586746059901158fae339d AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8443
ENV ASPNETCORE_HTTP_PORTS=8080
ENV ASPNETCORE_HTTPS_PORTS=8443
LABEL org.opencontainers.image.description="OpenID Connect (OIDC) & OAuth 2 API Server used to secure Kubernetes Ingress"

# renovate: datasource=repology depName=alpine_3_22/busybox versioning=loose
ENV BUSYBOX_VERSION="1.37.0-r18"

# renovate: datasource=repology depName=alpine_3_22/busybox-binsh versioning=loose
ENV BUSYBOX_BINSH_VERSION="1.37.0-r18"

# renovate: datasource=repology depName=alpine_3_22/ca-certificates-bundle versioning=loose
ENV CA_CERTIFICATES_BUNDLES_VERSION="20250619-r0"

# renovate: datasource=repology depName=alpine_3_22/libcrypto3 versioning=loose
ENV LIBCRYPTO3_VERSION="3.5.2-r0"

# renovate: datasource=repology depName=alpine_3_22/libgcc versioning=loose
ENV LIBGCC_VERSION="14.2.0-r6"

# renovate: datasource=repology depName=alpine_3_22/libssl3 versioning=loose
ENV LIBSSL3_VERSION="3.5.2-r0"

# renovate: datasource=repology depName=alpine_3_22/libstdc++ versioning=loose
ENV LIBSTDC_VERSION="14.2.0-r6"

# renovate: datasource=repology depName=alpine_3_22/ssl_client versioning=loose
ENV SSL_VERSION="1.37.0-r18"

# renovate: datasource=repology depName=alpine_3_22/zlib versioning=loose
ENV ZLIB_VERSION="1.3.1-r2"

RUN apk add --upgrade --no-cache \
        busybox>BUSYBOX_VERSION \
        busybox-binsh>$BUSYBOX_BINSH_VERSION \
        ca-certificates-bundle>$CA_CERTIFICATES_BUNDLES_VERSION \
        libcrypto3>$LIBCRYPTO3_VERSION \
        libgcc>$LIBGCC_VERSION \
        libssl3>$LIBSSL3_VERSION \
        libstdc++>$LIBSTDC_VERSION \
        ssl_client>$SSL_VERSION \
        zlib>$ZLIB_VERSION

USER $APP_UID

# This stage is used to build the service project
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine3.22@sha256:033283403fc5b8789467bb6a0f9670ebe0bc8f2276710cc99f1820f01789bafe AS build
ARG BUILD_CONFIGURATION=Release
ARG VERSION=0.0.1
WORKDIR /src
COPY ["oidc-guard.csproj", "."]
RUN dotnet restore "./oidc-guard.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "./oidc-guard.csproj" -c $BUILD_CONFIGURATION -o /app/build /p:Version=${VERSION}

# This stage is used to publish the service project to be copied to the final stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
ARG VERSION=0.0.1
RUN dotnet publish "./oidc-guard.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false /p:Version=${VERSION}

# This stage is used in production or when running from VS in regular mode (Default when not using the Debug configuration)
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "oidc-guard.dll"]