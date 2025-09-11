ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled@sha256:83795c4b066ec5f0610d8c3fdd977b65e7536c9bbade4f594e80e5fa24fb533a AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8443
ENV ASPNETCORE_HTTP_PORTS=8080
ENV ASPNETCORE_HTTPS_PORTS=8443
LABEL org.opencontainers.image.description="OpenID Connect (OIDC) & OAuth 2 API Server used to secure Kubernetes Ingress"

# renovate: datasource=repology depName=ubuntu_24_04/ca-certificates versioning=loose
ENV CA_CERTIFICATES_VERSION="20240203"

# renovate: datasource=repology depName=ubuntu_24_04/gcc-14 versioning=loose
ENV GCC_VERSION="14.2.0-4ubuntu2~24.04"

# renovate: datasource=repology depName=ubuntu_24_04/gcc-14-base versioning=loose
ENV GCC_BASE_VERSION="14.2.0-4ubuntu2~24.04"

# renovate: datasource=repology depName=ubuntu_24_04/libc6 versioning=loose
ENV LIBC_VERSION="2.39-0ubuntu8.5"

# renovate: datasource=repology depName=ubuntu_24_04/libgcc-s1 versioning=loose
ENV LIBGCC_VERSION="14.2.0-4ubuntu2~24.04"

# renovate: datasource=repology depName=ubuntu_24_04/libssl3t64 versioning=loose
ENV LIBSSL_VERSION="3.0.13-0ubuntu3.5"

# renovate: datasource=repology depName=ubuntu_24_04/libstdc++6 versioning=loose
ENV LIBSTDC_VERSION="14.2.0-4ubuntu2~24.04"

# renovate: datasource=repology depName=ubuntu_24_04/openssl versioning=loose
ENV OPENSSL_VERSION="3.0.13-0ubuntu3.5"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates=$CA_CERTIFICATES_VERSION \
       gcc-14=$GCC_VERSION \
       gcc-14-base=$GCC_BASE_VERSION \
       libc6=$LIBC_VERSION \
       libgcc-s1=$LIBGCC_VERSION \
       libssl3t64=$LIBSSL_VERSION \
       libstdc++6=$LIBSTDC_VERSION \
       openssl=$OPENSSL_VERSION \
    && rm -rf /var/lib/apt/lists/*

# This stage is used to build the service project
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:d599d654aa6fd7baabe54b4272dc475768307ef4d8a07d6e9f9b50b7b1758059 AS build
ARG BUILD_CONFIGURATION=Release
ARG VERSION=0.0.1
WORKDIR /src
COPY ["oidc-guard.csproj", "."]
RUN dotnet restore "./oidc-guard.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "./oidc-guard.csproj" -c $BUILD_CONFIGURATION -o /app/build

# This stage is used to publish the service project to be copied to the final stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
ARG VERSION=0.0.1
RUN dotnet publish "./oidc-guard.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# This stage is used in production or when running from VS in regular mode (Default when not using the Debug configuration)
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "oidc-guard.dll"]