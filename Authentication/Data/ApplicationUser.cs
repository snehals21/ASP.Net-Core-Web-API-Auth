using Microsoft.AspNetCore.Identity;

namespace Authentication.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
    }
}
