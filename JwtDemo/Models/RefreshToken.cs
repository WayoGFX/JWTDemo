namespace JwtDemo.Models;

public class RefreshToken
{
    public int Id {get; set;}
    public string Token {get; set;} = string.Empty;
    public DateTime Expires {get; set;}
    public bool Revoked {get; set;} = false;

    public int UserId {get; set;}
    public User User {get; set;} = null!;
}