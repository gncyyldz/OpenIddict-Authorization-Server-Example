using Microsoft.EntityFrameworkCore;
using System.Diagnostics.CodeAnalysis;

namespace OpenIddict.AuthorizationServer.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext([NotNullAttribute] DbContextOptions options) : base(options)
        {
        }
    }
}
