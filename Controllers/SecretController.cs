using System.Reflection.Metadata.Ecma335;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtDemo.Controllers;


[ApiController]
[Route("api/[controller]")]
public class SecretController : ControllerBase
{
    [HttpGet("message")]
    [Authorize]
    public IActionResult GetMessage()
    {
        var username = User.Identity?.Name;
        return Ok($"Hi {username}, this message is see only user authenticad");
    }

    [HttpGet("only-admin")]
    [Authorize(Roles = "Admin")]
    public IActionResult GetOnlyAdmin()
    {
        return Ok("This message only see as admin");
    }
}