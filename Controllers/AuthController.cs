using Microsoft.AspNetCore.Mvc;
using JwtDemo.Data;
using JwtDemo.Services;

namespace JwtDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly TokenService _tokenService;

    public AuthController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    // definimos el tipo de dato que se recibe
    public record LoginRequest(string Username, string Password);

    // endpoint to login
    [HttpPost("login")]
    // se recibe y envia informacion al servidor por eso IActionResult
    public IActionResult Login(LoginRequest request)
    {
        var user = FakeUserStore.Users.FirstOrDefault(u => u.Username == request.Username && u.Password == request.Password);

        // data validation
        if (user is null)
        {
            return Unauthorized("Username or Password wrong"); // es como enviar un 401, le dice al clienteque hay dato invalido
        }

        var accessToken = _tokenService.GenerateToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // save the refresh token in db 
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);

        return Ok(new {accessToken, refreshToken});
    }

    // for refresh token
    public record RefreshRequest(string Username, string RefreshToken);

    [HttpPost("refresh")]
    public IActionResult Refresh(RefreshRequest request)
    {
        var user = FakeUserStore.Users.FirstOrDefault(u => u.Username == request.Username);

        if (user is null || user.RefreshToken != request.RefreshToken)
        {
            return Unauthorized("Refresh invalid token");
        }
        if (user.RefreshTokenExpiry < DateTime.UtcNow)
        {
            return Unauthorized("Rfresh expired token, login again");
        }

        // if all god generate new acces token
        var newAccessToken = _tokenService.GenerateToken(user);

        // for security, also rotate the refresh token
        var newRefreshToken = _tokenService.GenerateRefreshToken();
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);

        return Ok(new{accessToken = newAccessToken, refreshToken = newRefreshToken});
    }
}