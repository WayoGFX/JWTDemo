using JwtDemo.Data;
using JwtDemo.Models;
using JwtDemo.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Identity;
using Microsoft.Extensions.Configuration;
using Xunit;
using Microsoft.AspNetCore.Identity;
using JwtDemo.Controllers;
using Microsoft.AspNetCore.Mvc;
using System.Drawing;
using Microsoft.EntityFrameworkCore.Query.Internal;
using System.Data.Common;


namespace JwtDemo.Tests.IntegrationTests;

public class AuthControllerTests
{
    private AppDbContext CrearDbContextEnMemoria()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString())
        .Options;

        return new AppDbContext(options);
    }

    private TokenService CrearTokenService()
    {
        var configValues = new Dictionary<string, string?>
        {
            {"Jwt:Key","clave-de-pruebas-suficientemente-larga-para-hs256-1234"},
            {"Jwt:Issuer","JwtDemoTests"},
            {"Jwt:Audience","JwtDemoTestClient"},
            {"Jwt:ExpiresInMinutes","4"},
        };

        IConfiguration config = new ConfigurationBuilder()
        .AddInMemoryCollection(configValues)
        .Build();

        return new TokenService(config);
    }

    [Fact]
    public async Task Register_ConDatosValidos_DebeCrearUsuario()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher,tokenService);
        var request = new AuthController.LoginRequest("wayo", "epickey123");

        // Act
        var result = await controller.Register(request);

        // Assert
        var userCreated = await db.Users.FirstOrDefaultAsync(u => u.Username == "wayo");
        Assert.NotNull(userCreated);
        Assert.NotEqual("epickey123", userCreated.PasswordHash); // don't plain text
    }

    [Fact]
    public async Task Register_UsuarioExistente_DeberiaRechazar()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db, hasher, tokenService);

        db.Users.Add(new User{Username = "wayo", PasswordHash = "test1234567"});
        await db.SaveChangesAsync();

        var request = new AuthController.LoginRequest("wayo","fifaworldcup2026");

        // Act
        var result = await controller.Register(request);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);

    }

    [Fact]
    public async Task Login_ConCredencialCorrecta_DebeDevolverTokens()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher, tokenService);
        var request = new AuthController.LoginRequest("wayo","123");

        await controller.Register(request); // method origin

        // Act
        var result = await controller.Login(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(okResult.Value);
    }

    [Fact]
    public async Task Login_ConUsuarioInexistente_DebeRechazar()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher,tokenService);
        var request = new AuthController.LoginRequest("wayo","234");

        await controller.Register(request);

        // Act
        var result = await controller.Login(new AuthController.LoginRequest("oway","6767"));
        
        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Login_ConPasswordIncorrecta_DeberiaRechazar()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher, tokenService);
        var request = new AuthController.LoginRequest("wayo","123");

        await controller.Register(request); // method origin

        // Act
        var result = await controller.Login(new AuthController.LoginRequest("wayo","hellothispasswordisnotcorrect"));

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task LogoutUser_ConTokenInexistente_DebeRechazar()
    {
       // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher, tokenService);

        // Act
        var result = await controller.Logout(new AuthController.RefreshRequest("tokeninexistente2026"));

        // Assert
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task LogoutUser_ConTokenExpirado_DebeRechazar()
    {
       // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher, tokenService);
        var user = new User {Username = "wayo", PasswordHash = "12367"};
        db.Users.Add(user);
        await db.SaveChangesAsync();
        
        var refreshToken = new RefreshToken
        {
            Token = "token-vencido-456",
            Expires = DateTime.UtcNow.AddDays(-1),
            Revoked = false,
            UserId = user.Id
        };
        db.RefreshTokens.Add(refreshToken);
        await db.SaveChangesAsync();

        // Act
        var result = await controller.Logout(new AuthController.RefreshRequest("token-vencido-456"));

        // Assert
        Assert.IsType<OkObjectResult>(result);

        var tokenEnBd = await db.RefreshTokens.FirstAsync(rt => rt.Token == "token-vencido-456");
        Assert.True(tokenEnBd.Revoked);
    }

    // REFRESH
    [Fact]
    public async Task Refresh_ConTokenInexistente_DeberiaRechazar()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher, tokenService);

        var request = new AuthController.RefreshRequest("inexistenttokentest123");
        
        // Act
        var result = await controller.Refresh(request);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Refresh_ConTokenRevocado_DeberiaRechazar()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher, tokenService);

        var user = new User {Username = "wayo", PasswordHash = "12367"};
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var refreshToken = new RefreshToken
        {
            Token = "token-revocado-123",
            Expires = DateTime.UtcNow.AddDays(7),
            Revoked = true,
            UserId = user.Id
        };
        db.RefreshTokens.Add(refreshToken);
        await db.SaveChangesAsync();

        var request = new AuthController.RefreshRequest("token-revocado-123");

        // Act
        var result = await controller.Refresh(request);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);

    }

    [Fact]
    public async Task Refresh_ConTokenExpirado_DeberiaRechazar()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher, tokenService);

        var user = new User {Username = "wayo", PasswordHash = "12367"};
        db.Users.Add(user);
        await db.SaveChangesAsync();
        
        var refreshToken = new RefreshToken
        {
            Token = "token-vencido-456",
            Expires = DateTime.UtcNow.AddDays(-1),
            Revoked = false,
            UserId = user.Id
        };
        db.RefreshTokens.Add(refreshToken);
        await db.SaveChangesAsync();
        var request = new AuthController.RefreshRequest("token-vencido-456");

        // Act
        var result = await controller.Refresh(request);

        // Assert
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Refresh_D_Deberia()
    {
        // Arrange
        var db = CrearDbContextEnMemoria();
        var hasher = new PasswordHasher<User>();
        var tokenService = CrearTokenService();
        var controller = new AuthController(db,hasher, tokenService);
        
        var user = new User {Username = "wayo", PasswordHash = "12367"};
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var refreshTokenOrigin = new RefreshToken
        {
            Token = "token-valido-670",
            Expires = DateTime.UtcNow.AddDays(7),
            Revoked = false,
            UserId = user.Id
        };
        db.RefreshTokens.Add(refreshTokenOrigin);
        await db.SaveChangesAsync();
        var request = new AuthController.RefreshRequest("token-valido-670");

        // Act
        var result = await controller.Refresh(request);



        // Assert
        Assert.IsType<OkObjectResult>(result);

        //verificar rotation in db
        var tokenViejo = await db.RefreshTokens.FirstAsync(rt => rt.Token == "token-valido-670");
        Assert.True(tokenViejo.Revoked); // the old is revoked

        var cantidadTokens = await db.RefreshTokens.CountAsync(rt => rt.UserId == user.Id);
        Assert.Equal(2, cantidadTokens); // the old + new token generated
    }
}