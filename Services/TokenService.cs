using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using JwtDemo.Models;
namespace JwtDemo.Services;

public class TokenService
{
    private readonly IConfiguration _config;

    // instance of the Data
    public TokenService(IConfiguration config)
    {
        _config = config;
    }

    public string GenerateToken(User user)
    {
        // 1. Claims . data in token about this user | osea los datos que van dentro del token de usuario
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

        // 2. Secret key, convert to format that require the library | practicamente es preparar el hash
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));

        // 3. Credentials of firm: key + algoritm 
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Make the token with all info | preparar toda la info para el token
        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(double.Parse(_config["Jwt:ExpiresInMinutes"]!)),
            signingCredentials: creds
        );

        // 5. Convert to string (this send to client)
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}