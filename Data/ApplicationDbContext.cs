using Authorization.Model;
using Microsoft.EntityFrameworkCore;

namespace Authorization.Data;

public class ApplicationDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public ApplicationDbContext(DbContextOptions options) : base(options)
    {
       
    }
}
