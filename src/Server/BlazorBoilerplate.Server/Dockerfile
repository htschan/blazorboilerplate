#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["nuget.config", "."]
COPY ["Server/BlazorBoilerplate.Server/BlazorBoilerplate.Server.csproj", "Server/BlazorBoilerplate.Server/"]
COPY ["Shared/Modules/BlazorBoilerplate.Theme.Material.Demo/BlazorBoilerplate.Theme.Material.Demo.csproj", "Shared/Modules/BlazorBoilerplate.Theme.Material.Demo/"]
COPY ["Shared/Modules/BlazorBoilerplate.Theme.Material/BlazorBoilerplate.Theme.Material.csproj", "Shared/Modules/BlazorBoilerplate.Theme.Material/"]
COPY ["Shared/BlazorBoilerplate.Shared/BlazorBoilerplate.Shared.csproj", "Shared/BlazorBoilerplate.Shared/"]
COPY ["Shared/BlazorBoilerplate.Infrastructure.AuthorizationDefinitions/BlazorBoilerplate.Infrastructure.AuthorizationDefinitions.csproj", "Shared/BlazorBoilerplate.Infrastructure.AuthorizationDefinitions/"]
COPY ["Shared/BlazorBoilerplate.Constants/BlazorBoilerplate.Constants.csproj", "Shared/BlazorBoilerplate.Constants/"]
COPY ["Shared/BlazorBoilerplate.Shared.DataInterfaces/BlazorBoilerplate.Shared.DataInterfaces.csproj", "Shared/BlazorBoilerplate.Shared.DataInterfaces/"]
COPY ["Shared/BlazorBoilerplate.Shared.Localizer/BlazorBoilerplate.Shared.Localizer.csproj", "Shared/BlazorBoilerplate.Shared.Localizer/"]
COPY ["Utils/BlazorBoilerplate.SourceGenerator/BlazorBoilerplate.SourceGenerator.csproj", "Utils/BlazorBoilerplate.SourceGenerator/"]
COPY ["Client/BlazorBoilerplate.Client/BlazorBoilerplate.Client.csproj", "Client/BlazorBoilerplate.Client/"]
COPY ["Shared/Modules/BlazorBoilerplate.Theme.Material.Admin/BlazorBoilerplate.Theme.Material.Admin.csproj", "Shared/Modules/BlazorBoilerplate.Theme.Material.Admin/"]
COPY ["Shared/BlazorBoilerplate.Infrastructure/BlazorBoilerplate.Infrastructure.csproj", "Shared/BlazorBoilerplate.Infrastructure/"]
COPY ["Shared/BlazorBoilerplate.Infrastructure.Storage/BlazorBoilerplate.Infrastructure.Storage.csproj", "Shared/BlazorBoilerplate.Infrastructure.Storage/"]
COPY ["Server/BlazorBoilerplate.Storage/BlazorBoilerplate.Storage.csproj", "Server/BlazorBoilerplate.Storage/"]
COPY ["nupkg/*","nupkg/"]
RUN dotnet restore "Server/BlazorBoilerplate.Server/BlazorBoilerplate.Server.csproj"
COPY . .
WORKDIR "/src/Server/BlazorBoilerplate.Server"
RUN dotnet build "BlazorBoilerplate.Server.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "BlazorBoilerplate.Server.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "BlazorBoilerplate.Server.dll"]