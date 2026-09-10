using JwtDemo.Models;

namespace JwtDemo.Data;

public static class FakeUserStore
{
    public static List<User> Users = new()
    {
        new User {Id = 1, Username = "wayo", Password = "123", Role = "Admin"},
        new User {Id = 2, Username = "pau", Password = "abcd", Role = "User"}
    };
}