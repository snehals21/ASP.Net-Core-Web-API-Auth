using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Authentication.Data;
using Authentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserAuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly string? _jwtkey;
        private readonly string? _jwtIssuer;
        private readonly string? _jwtAudience;
        private readonly int _jwtExpiry;

        public UserAuthController(
            UserManager<ApplicationUser> userManager, 
            SignInManager<ApplicationUser> signInManager, 
            IConfiguration configuration) 
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtkey = configuration["Jwt:Key"];
            _jwtIssuer = configuration["Jwt:Issuer"];
            _jwtAudience = configuration["Jwt:Audience"];
            _jwtExpiry = 60;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            if (registerModel == null
                || string.IsNullOrEmpty(registerModel.Name)
                || string.IsNullOrEmpty(registerModel.Email)
                || string.IsNullOrEmpty(registerModel.Password))
            {
                return BadRequest("Invalid or missing data.");
            }

            var existingUser = await _userManager.FindByEmailAsync(registerModel.Email);
            if (existingUser != null)
            {
                return Conflict("Email is already exists.");
            }

            var user = new ApplicationUser
            {
                Name = registerModel.Name,
                Email = registerModel.Email,
                UserName = registerModel.Email,
            };

            var result = await _userManager.CreateAsync(user, registerModel.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok("User created");
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.Email);
            if (user == null)
            {
                return Unauthorized(new { success = false, message = "Unauthorized." });
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, loginModel.Password, false);

            if (!result.Succeeded)
            {
                return Unauthorized(new { success = false, message = "Unauthorized." });
            }

            var token = GenerateJwtToken(user);
            return Ok(new { success = true, token });

        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var Claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("name", user.Name),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtkey));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims: Claims,
                expires: DateTime.Now.AddMinutes(_jwtExpiry),
                signingCredentials: creds);
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return Ok("Logged out successfully.");
        }
    }
}
