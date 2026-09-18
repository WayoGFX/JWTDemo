using Microsoft.AspNetCore.Mvc;
using JwtDemo.Data;
using JwtDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.AspNetCore.Identity;
using JwtDemo.Models;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace JwtDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{

    private readonly AppDbContext _db;
    private readonly IPasswordHasher<User> _hasher;
    private readonly TokenService _tokenService;

    public AuthController(AppDbContext db, IPasswordHasher<User> hasher, TokenService tokenService)
    {
        _db = db;
        _hasher = hasher;
        _tokenService = tokenService;
    }
    public record LoginRequest(string Username, string Password);

    [HttpPost("register")]
    public async Task<IActionResult> Register(LoginRequest request)
    {
        if (await _db.Users.AnyAsync(u => u.Username == request.Username))
        {
            return BadRequest("User already exist");
        }
        var user = new User {Username = request.Username, Role = "User"};
        user.PasswordHash = _hasher.HashPassword(user,request.Password);

        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        
        return Ok("User created");
    }

    // endpoint to login
    [HttpPost("login")]
    // se recibe y envia informacion al servidor por eso IActionResult
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

        // user already exist validation
        if (user is null)
        {
            return Unauthorized("Username or Password is wrong"); // es como enviar un 401, le dice al clienteque hay dato invalido
        }

        // user password hash validations
        var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
        if (result == PasswordVerificationResult.Failed)
        {
            return Unauthorized("Username or Password is wrong"); // es como enviar un 401, le dice al clienteque hay dato invalido
        }

        var accessToken = _tokenService.GenerateToken(user);
        var refreshToken = new RefreshToken
        {
            Token = _tokenService.GenerateRefreshToken(),
            Expires = DateTime.UtcNow.AddDays(7),
            UserId = user.Id
        };

        // save the refresh token in db 
        _db.RefreshTokens.Add(refreshToken);
        await _db.SaveChangesAsync();

        return Ok(new {accessToken, refreshToken = refreshToken.Token});
    }

    // for refresh token
    public record RefreshRequest(string RefreshToken);

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(RefreshRequest request)
    {
        var storedToken = await _db.RefreshTokens
        .Include(rt => rt.User)
        .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

        if (storedToken is null || storedToken.Revoked || storedToken.Expires < DateTime.UtcNow)
        {
            return Unauthorized("Refresh token invalid");
        }

        // rotation: revoked the old and create a new
        storedToken.Revoked = true;

        var newAccessToken = _tokenService.GenerateToken(storedToken.User);
        var newRefreshToken = new RefreshToken
        {
            // for security, also rotate the refresh token
            Token = _tokenService.GenerateRefreshToken(),
            Expires = DateTime.UtcNow.AddDays(7),
            UserId = storedToken.UserId
        };

        _db.RefreshTokens.Add(newRefreshToken);
        await _db.SaveChangesAsync();    

        return Ok(new{accessToken = newAccessToken, refreshToken = newRefreshToken.Token});
    }

    // logout

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout(RefreshRequest request)
    {
        var storedToken = await _db.RefreshTokens
        .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

        if (storedToken is null)
        {
            return NotFound();
        }

        storedToken.Revoked = true;
        await _db.SaveChangesAsync();

        return Ok("Close session");
    }
}