using System.ComponentModel.DataAnnotations;

namespace Authorization.Model;

public class UserDto
{
    [Required]
    [StringLength(50)]
    public required string Name { get; set; }

    [Required]
    [EmailAddress]
    public required string EmailAddress { get; set; }

    [Required]
    public required string Role { get; set; }

    [Required]
    [MinLength(8)]
    public required string Password { get; set; }
}
