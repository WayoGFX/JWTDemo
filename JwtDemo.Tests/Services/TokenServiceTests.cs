using Microsoft.Extensions.Configuration;
using JwtDemo.Data;
using JwtDemo.Models;
using Xunit;

using JwtDemo.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JwtDemo.Tests;


public class TokenServiceTests
{
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
    public void GenerateToken_DeberiaRetornarUnStringNoVacio()
    {
        // Arrange
        var tokenService = CrearTokenService();
        var user = new User {Id = 1, Username = "wayo", Role = "Admin"};

        // Act
        var token = tokenService.GenerateToken(user);

        // Assert
        Assert.False(string.IsNullOrEmpty(token));
    }


    [Fact]
    public void GenerateToken_DeberiaIncluirLosClaimCorrectos()
    {
        // Arrange
        var tokenService = CrearTokenService();
        var user = new User {Id = 67, Username = "pau", Role = "Admin"};

        // Act
        var token = tokenService.GenerateToken(user);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        Assert.Equal("67", jwt.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value);
        Assert.Equal("pau", jwt.Claims.First(c => c.Type == ClaimTypes.Name).Value);
        Assert.Equal("Admin", jwt.Claims.First(c => c.Type == ClaimTypes.Role).Value);
    }

    [Fact]
    public void GenerateToken_DeberiaExpirarEnElTiempoConfigurado()
    {
        // Arrange
        var tokenService = CrearTokenService(); // configrate 15 minutes
        var user = new User {Id = 1, Username = "wayo", Role = "User"};
        var antesDeGenerar = DateTime.UtcNow;

        // Act
        var token = tokenService.GenerateToken(user);

        // Assert
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        var expiracionEsperada = antesDeGenerar.AddMinutes(4);
        var diferenciaEnSegundos = (jwt.ValidTo - expiracionEsperada).TotalSeconds;

        // margen de segundos por el tiempo que tarda en ejecutarse el test
        Assert.True(
            Math.Abs(diferenciaEnSegundos) < 5,
            $"Diferencia de {diferenciaEnSegundos} segundos. ValidTo={jwt.ValidTo:o}, Esperado={expiracionEsperada:o}"
        );
    }

    [Theory]
    [InlineData("Admin")]
    [InlineData("User")]
    [InlineData("Invitado")]
    public void GenrateToken_DeberiaRespetarElRolDelUsuario(string rol)
    {
        // Arrange
        var tokenService = CrearTokenService();
        var user = new User{Id = 1, Username = "testUser", Role = rol};

        // Act
        var token = tokenService.GenerateToken(user);

        // Assert
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        Assert.Equal(rol, jwt.Claims.First(c => c.Type == ClaimTypes.Role).Value);
    }

    [Fact]
    public void GenerateRefreshToken_DeberiaGenerarValoresUnicos()
    {
        // Arrange
        var tokenService = CrearTokenService();

        // Act
        var token1 = tokenService.GenerateRefreshToken();
        var token2 = tokenService.GenerateRefreshToken();

        // Assert
        Assert.NotEqual(token1, token2);

    }
}