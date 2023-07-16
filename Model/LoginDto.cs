using System.ComponentModel.DataAnnotations;

namespace Authorization.Model;

public class LoginDto
{
    [Required]
    [EmailAddress]
    public required string EmailAddress { get; set; }

    [Required]
    public required string Password { get; set; }
}
