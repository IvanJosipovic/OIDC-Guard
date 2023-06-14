ARG BUILDPLATFORM=linux/amd64

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:7.0-alpine@sha256:895ef6f8758fd192814bf46a74b2922d00863f4b51f7fa231295a9e38031fda2 AS build
WORKDIR /src
COPY OIDC-Guard.csproj .
RUN dotnet restore "OIDC-Guard.csproj"
COPY . .
RUN dotnet build "OIDC-Guard.csproj" -c Release -o /app/build

FROM build AS publish
ARG VERSION=0.0.1
RUN dotnet publish "OIDC-Guard.csproj" -c Release --use-current-runtime -o /app/publish /p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:7.0-alpine@sha256:215aa60901170ed051969d6b05832853ccf669af90718658f76de8e27ca983ce AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

RUN apk update && \
    apk upgrade && \
    rm -rf /var/cache/apk/*

RUN addgroup -g 2000 appgroup \
    && adduser -u 1000 -G appgroup -D "appuser"

RUN chown appuser:appgroup  /app
USER appuser:appgroup

COPY --from=publish /app/publish .
ENTRYPOINT ["./OIDC-Guard"]