<div id="top"></div>

[![Deploy To NuGet Registry](https://github.com/Tuckfirtle/Tuckfirtle.OpenQuantumSafe/actions/workflows/build_oqs.yml/badge.svg)](https://github.com/Tuckfirtle/Tuckfirtle.OpenQuantumSafe/actions/workflows/build_oqs.yml)


# Tuckfirtle.OpenQuantumSafe
Tuckfirtle open quantum safe wrapper.

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#license">License</a></li>
  </ol>
</details>

## About This Library

This library provides native wrapper for [Open Quantum Safe](https://openquantumsafe.org/).

<p align="right">(<a href="#top">back to top</a>)</p>

### Built With

* [dotnet 6.0](https://dotnet.microsoft.com/download/dotnet/6.0)

<p align="right">(<a href="#top">back to top</a>)</p>

## Getting Started

Follow the instructions below to install this library on your project.

### Prerequisites

You must use a personal access token with the appropriate scopes to install packages in GitHub Packages. For more information, see "[About GitHub Packages](https://docs.github.com/en/packages/learn-github-packages/about-github-packages#authenticating-to-github-packages)."

You must replace:
* `USERNAME` with the name of your user account on GitHub.
* `TOKEN` with your personal access token.

via dotnet command-line interface (CLI) (persistent)

```sh
dotnet nuget add source -n "github/Tuckfirtle" -u USERNAME -p TOKEN --store-password-in-clear-text https://nuget.pkg.github.com/Tuckfirtle/index.json
```

via nuget.config (per project)

Create nuget.config and insert this into the solution.

Note: If you are working on an open source project, you have to add this file into `.gitignore` if you are sharing into git repository.

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <packageSources>
        <add key="github" value="https://nuget.pkg.github.com/Tuckfirtle/index.json" />
    </packageSources>
    <packageSourceCredentials>
        <github>
            <add key="Username" value="USERNAME" />
            <add key="ClearTextPassword" value="TOKEN" />
        </github>
    </packageSourceCredentials>
</configuration>
```

### Installation

via dotnet command-line interface (CLI)

To use this package, run the command line below with the version you want to use:

```sh
dotnet add package Tuckfirtle.OpenQuantumSafe --version 1.0.0
```

via .csproj file

To use this package, add `ItemGroup` and configure the `PackageReference` field in the .csproj project file with the version you want to use:

```xml
<ItemGroup>
    <PackageReference Include="Tuckfirtle.OpenQuantumSafe" Version="1.0.0" />
</ItemGroup>
```

<p align="right">(<a href="#top">back to top</a>)</p>

## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>
