#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0-preview AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0-preview AS build
WORKDIR /src
COPY ["OIDC-Guard.csproj", "."]
RUN dotnet restore "./OIDC-Guard.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "OIDC-Guard.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "OIDC-Guard.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "OIDC-Guard.dll"]