using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ToDoController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JWTDbContext _context;
        private readonly JwtSecurityTokenHandler _tokenHandler;

        public ToDoController(
            IConfiguration config,
            UserManager<IdentityUser> userManager,
            JWTDbContext context)
        {
            _config = config;
            _userManager = userManager;
            _context = context;
            _tokenHandler = new JwtSecurityTokenHandler();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequestModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                return Unauthorized("Invalid username or password");
            }

            var (accessToken, refreshToken) = GenerateJwtTokens(user);

            return Ok(new LoginResponseModel
            {
                Token = accessToken,
                RefreshToken = refreshToken
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequestModel model)
        {
            var user = new IdentityUser { UserName = model.UserName };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok(new { message = "User registered successfully" });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(RefreshTokenRequestModel model)
        {
            var refreshToken = await _context.RefreshTokens.FindAsync(model.RefreshToken);
            if (refreshToken == null || refreshToken.ExpiryDate <= DateTime.UtcNow)
            {
                return Unauthorized("Invalid or expired refresh token");
            }

            var user = await _userManager.FindByNameAsync(refreshToken.UserName);
            if (user == null)
            {
                return Unauthorized("Invalid refresh token");
            }

            var (accessToken, newRefreshToken) = GenerateJwtTokens(user);

            refreshToken.Token = newRefreshToken;
            refreshToken.ExpiryDate = DateTime.UtcNow.AddDays(7);
            await _context.SaveChangesAsync();

            return Ok(new LoginResponseModel
            {
                Token = accessToken,
                RefreshToken = newRefreshToken
            });
        }

        private (string, string) GenerateJwtTokens(IdentityUser user)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.UserName)
                }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_config["JWT:Key"])),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var accessToken = _tokenHandler.WriteToken(_tokenHandler.CreateToken(tokenDescriptor));
            var refreshToken = GenerateRefreshToken();

            _context.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                UserName = user.UserName,
                ExpiryDate = DateTime.UtcNow.AddDays(7)
            });

            return (accessToken, refreshToken);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }

    public class LoginRequestModel
    {
        [Required] public string UserName { get; set; }
        [Required] public string Password { get; set; }
    }

    public class RegisterRequestModel
    {
        [Required] public string UserName { get; set; }
        [Required] public string Password { get; set; }
    }

    public class LoginResponseModel
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }

    public class RefreshTokenRequestModel
    {
        public string RefreshToken { get; set; }
    }

    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; }
        public string UserName { get; set; }
        public DateTime ExpiryDate { get; set; }
    }
}
