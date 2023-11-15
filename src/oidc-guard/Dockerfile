ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:4c2ed06d729b26c96c3b0e64c98356058c1ad342c54b08238434f0ef05d70bfa AS build
WORKDIR /src
COPY oidc-guard.csproj .
RUN dotnet restore "oidc-guard.csproj"
COPY . .
RUN dotnet build "oidc-guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "oidc-guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-alpine@sha256:2ec1a344a016a6c9fb4828a5df017bbf8237defc4f64c0a4ee6479b4a44b3ec9 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
LABEL org.opencontainers.image.description OpenID Connect (OIDC) Proxy Server for securing Kubernetes Ingress

RUN apk update && \
    apk upgrade && \
    rm -rf /var/cache/apk/*

USER app

COPY --from=publish /app/publish .
ENTRYPOINT ["./oidc-guard"]