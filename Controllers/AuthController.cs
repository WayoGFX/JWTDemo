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

        // if all correct generate token
        var token = _tokenService.GenerateToken(user);
        return Ok(new {token});
    }
}