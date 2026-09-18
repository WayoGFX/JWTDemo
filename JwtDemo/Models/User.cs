namespace JwtDemo.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "User";

    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}