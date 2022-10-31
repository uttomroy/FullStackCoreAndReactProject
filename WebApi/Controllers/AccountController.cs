using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebApi.Controllers
{
    [Route("api/[Controller]/")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        [HttpGet]
        public string LogIn()
        {
            var issuer = "https://joydipkanjilal.com/";
            var audience = "https://joydipkanjilal.com/";
            var key = Encoding.ASCII.GetBytes
            ("THIS_123458-788889");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id", Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Sub, "12347"),
                    new Claim(JwtRegisteredClaimNames.Email, "126598@gmail.com"),
                    new Claim(JwtRegisteredClaimNames.Jti,
                Guid.NewGuid().ToString())
                , new Claim(ClaimTypes.Role, "Admin")
                }),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials
                (new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha512Signature)
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = tokenHandler.WriteToken(token);
            var stringToken = tokenHandler.WriteToken(token);
            HttpContext.Response.Cookies.Append("Name", "Pradasdfasdfip");
            HttpContext.Response.Cookies.Append("adfasdf", "Pradasdfasdfip");
            return stringToken;
        }

        [HttpGet("{id}")]
        [Authorize(Roles = "Admin")]
        public int Logout(int id)
        {
            return id;
        }
    }
}
