using Authorization.Data;
using Authorization.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authorization.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IConfiguration _config;
    public AuthController(ApplicationDbContext dbContext, IConfiguration config)
    {
        _dbContext = dbContext;
        _config = config;

    }


    [HttpGet]
    [Authorize(Roles = "admin")]
    public async Task<IActionResult> Get()
    {
        var user = await _dbContext.Users.ToListAsync();
        return Ok(user);
    }

    [HttpGet("{id}", Name = "GetById")]
    [Authorize(Roles = "admin, editor, user")]
    public async Task<IActionResult> Get(int id)
    {
        int claimedId = Convert.ToInt32( User.FindFirst(ClaimTypes.NameIdentifier)!.Value );
        var claimedRole = User.FindFirst(ClaimTypes.Role)!.Value;

        if (id != claimedId && claimedRole != "admin")
        {
            return Forbid();
        }

        var user = await _dbContext.Users.FirstOrDefaultAsync(x => x.Id == id);
        if (user is null)
        {
            return NotFound();
        }
        return Ok(user);

    }

    [AllowAnonymous]
    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(x => x.Id == id);
        if (user is null)
        {
            return NotFound();
        }
        _dbContext.Users.Remove(user);
        await _dbContext.SaveChangesAsync();
        return NoContent();
    }

    [AllowAnonymous]
    [HttpPost("/register")]
    public async Task<IActionResult> Register(UserDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest();
        }
        var (hash, salt) = GenerateHashAndSalt(request.Password);

        var user = new User 
        { 
            Name = request.Name, 
            EmailAddress = request.EmailAddress,
            Role = request.Role,
            PasswordHash = hash,
            PasswordSalt = salt,
        };
        await _dbContext.Users.AddAsync(user);

        await _dbContext.SaveChangesAsync();

        return CreatedAtRoute("GetById", new { user.Id }, user);
    }


    [AllowAnonymous]
    [HttpPost("/login")]
    public async Task<IActionResult> Login([FromBody] LoginDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest();
        }
        bool isMatched = await Verify(request);

        if (!isMatched)
        {
            return BadRequest("Email or password is invalid");
        }
        var user = await _dbContext.Users.FirstOrDefaultAsync(x => x.EmailAddress == request.EmailAddress);
        var token = GenerateToken(user!);
        return Ok(token);
    }

    private (byte[], byte[]) GenerateHashAndSalt(string password)
    {
        using (var hmac = new HMACSHA512())
        {
            var salt = hmac.Key;
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

            return (hash, salt);
        }
    }

    private async Task<bool> Verify(LoginDto loginDto)
    {
        var user = await _dbContext.Users.AsNoTracking().FirstOrDefaultAsync(x => x.EmailAddress == loginDto.EmailAddress);
        if (user is null)
        {
            return false;
        }

        using (var hmac = new HMACSHA512(user.PasswordSalt))
        {
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            // Compare byte arrays
            if (computedHash.SequenceEqual(user.PasswordHash))
            {
                return true;
            }
        }

        return false;
    }




    private string GenerateToken(User user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new Claim[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Name),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(ClaimTypes.Email, user.EmailAddress),
        };

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials
            );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

