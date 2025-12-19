# =========================
# Build stage
# =========================
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
WORKDIR /src

COPY ["API.Gateway/API.Gateway.csproj", "API.Gateway/"]
RUN dotnet restore "API.Gateway/API.Gateway.csproj"

COPY . .
WORKDIR /src/API.Gateway
RUN dotnet publish "API.Gateway.csproj" \
    -c Release \
    -o /app/publish \
    /p:UseAppHost=false

# =========================
# Runtime stage (lightweight)
# =========================
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine
WORKDIR /app
EXPOSE 8080

COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "API.Gateway.dll"]
