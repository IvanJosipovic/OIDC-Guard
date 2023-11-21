ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0@sha256:8660607969015201ce9f2103db5888f99776314d074234ca1aeb2961040b5fc6 AS build
WORKDIR /src
COPY oidc-guard.csproj .
RUN dotnet restore "oidc-guard.csproj"
COPY . .
RUN dotnet build "oidc-guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "oidc-guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-jammy-chiseled@sha256:b2d7564d74260ec88ebcbf42ecbfe2f6901cdf06de77c460054339e500fd2e48 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
LABEL org.opencontainers.image.description OpenID Connect (OIDC) Proxy Server for securing Kubernetes Ingress

USER app

COPY --from=publish /app/publish .
ENTRYPOINT ["./oidc-guard"]
