using JWTInWEB.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTInWEB.Controllers
{
    public class TokenController : Controller
    {
        private readonly IConfiguration _configuration;

        public TokenController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IActionResult Login()
        {
            return View();  
        }

        [HttpPost]
        public IActionResult Login(LoginModel model)
        {
            // TODO: Implement proper user authentication here
            // For simplicity, a dummy check is performed here
            if (model.username == "abc" && model.username == "abc")
            {
                var token = GenerateToken(model.username);
                HttpContext.Session.SetString("AccessToken", token);
                return Ok(new { Token = token });
            }

            return Unauthorized();
        }

        private string GenerateToken(string username)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var authClaims = new List<Claim>();

            authClaims.Add(new Claim(ClaimTypes.Name, "user.FirstName + user.LastName"));
            authClaims.Add(new Claim("UserName", "user.FirstName +  + user.LastName"));
            authClaims.Add(new Claim("Email", "user.Email"));
            authClaims.Add(new Claim("UserId", "user.Id"));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: authClaims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
