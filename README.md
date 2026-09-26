# JwtDemo

![CI](https://github.com/WayoGFX/JwtDemo/actions/workflows/ci.yml/badge.svg)

API in ASP.NET Core with complete JWT authentication: access token, refresh tokens with rotation, revocation and persistence in SQL Server with Entity Framework Core

## Features

- Register and Login with password hash (`PasswordHasher<User>`)
- Auth with JWT (HS256), validation of issuer/audience/expiration
- Refresh tokens with automatic rotation and revoked (logout)
- Endpoints protected with `[Authorize]` and roles (`[Authorize(Role = "Admin")]`)
- 17 tests with xUnit (unit test for `TokenService` + integration tests for `AuthController` with EF Core InMemory)
- CI pipeline with GitHub Actions (build + tests on each push/PR)


## Stack

C# · ASP.NET Core · Entity Framework Core · SQL Server · xUnit · GitHub Actions

## How to run locally

\`\`\`bash
git clone https://github.com/WayoGFX/JwtDemo.git
cd JwtDemo
# Configure appsettings.Development.json with your key and connection string
dotnet ef database update
dotnet run
\`\`\`

## Running tests

\`\`\`bash
dotnet test
\`\`\`

