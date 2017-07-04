using LagoVista.IoT.Web.Common.Controllers;
using System;
using LagoVista.Core.PlatformSupport;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.Core.Authentication.Models;
using LagoVista.Core.Networking.Models;
using LagoVista.AspNetCore.Identity.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using LagoVista.IoT.Web.Common.Claims;
using LagoVista.IoT.Logging.Loggers;

namespace LagoVista.UserAdmin.Rest
{
    /// <summary>
    /// Authentication Services
    /// </summary>
    [AllowAnonymous]
    public class AuthServices : LagoVistaBaseController
    {
        private readonly TokenAuthOptions _tokenOptions;
        ILogger _logger;

        private SignInManager<AppUser> _signInManager;
        private UserManager<AppUser> _userManager;

        public const string None = "-";
        public const string Surname = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";
        public const string NameIdentifier = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

        public AuthServices(TokenAuthOptions tokenOptions, IAdminLogger logger, SignInManager<AppUser> signInManager, UserManager<AppUser> userManager) : base(userManager, logger)
        {
            _tokenOptions = tokenOptions;
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        private async Task<APIResponse<AuthResponse>> Auth(AuthRequest req)
        {
            if (req.GrantType == "password")
            {
                var result = await _signInManager.PasswordSignInAsync(req.UserName, req.Password, true, false);
                if (result.Succeeded)
                {
                    var appUser = await _userManager.FindByNameAsync(req.UserName);

                    var expires = DateTime.UtcNow.AddDays(_tokenOptions.Expiration.TotalDays);
                    var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                    var offset = DateTimeOffset.Now;

                    var token = GetToken(appUser, expires);
                    var authResponse = new AuthResponse()
                    {
                        AuthToken = token,
                        TokenType = "auth",
                        AuthTokenExpiration = offset.ToUnixTimeSeconds()
                    };

                    return APIResponse<AuthResponse>.Create(authResponse);
                }

                return APIResponse<AuthResponse>.FromFailedStatusCode(System.Net.HttpStatusCode.Unauthorized);
            }
            else if(req.GrantType == "refresh")
            {
                //TODO: (and VERY important need to add logic for refresh tokens and auth that, not just blindly accept requests.
                var appUser = await _userManager.FindByNameAsync(req.UserName);

                var expires = DateTime.UtcNow.AddDays(_tokenOptions.Expiration.TotalDays);
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var offset = DateTimeOffset.Now;

                var token = GetToken(appUser, expires);
                var authResponse = new AuthResponse()
                {
                    AuthToken = token,
                    TokenType = "auth",
                    AuthTokenExpiration = offset.ToUnixTimeSeconds()
                };

                return APIResponse<AuthResponse>.Create(authResponse);
            }
            else
            {
                return APIResponse<AuthResponse>.FromFailedStatusCode(System.Net.HttpStatusCode.Unauthorized);
            }
        }



        private string GetToken(AppUser user, DateTime? expires)
        {
            var handler = new JwtSecurityTokenHandler();


            var now = DateTime.UtcNow;

            // Specifically add the jti (nonce), iat (issued timestamp), and sub (subject/user) claims.
            // You can add other claims here, if you want:
            var claims = new Claim[]
            {
                new Claim(System.Security.Claims.ClaimTypes.NameIdentifier, user.UserName),
                new Claim(System.Security.Claims.ClaimTypes.GivenName, user.FirstName),
                new Claim(System.Security.Claims.ClaimTypes.Surname, user.LastName),
                new Claim(System.Security.Claims.ClaimTypes.Email, user.Email),
                new Claim(ClaimsPrincipalFactory.CurrentUserId, user.Id),
                new Claim(ClaimsPrincipalFactory.EmailVerified, user.EmailConfirmed.ToString()),
                new Claim(ClaimsPrincipalFactory.PhoneVerfiied, user.PhoneNumberConfirmed.ToString()),
                new Claim(ClaimsPrincipalFactory.IsSystemAdmin, user.IsSystemAdmin.ToString()),
                new Claim(ClaimsPrincipalFactory.CurrentOrgName, user.CurrentOrganization == null ? None : user.CurrentOrganization.Text),
                new Claim(ClaimsPrincipalFactory.CurrentOrgId, user.CurrentOrganization == null ? None : user.CurrentOrganization.Id),
                new Claim(ClaimsPrincipalFactory.CurrentUserProfilePictureurl, user.ProfileImageUrl.ImageUrl),

                new Claim(JwtRegisteredClaimNames.Jti, NonceGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUniversalTime().ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            // Create the JWT and write it to a string
            var jwt = new JwtSecurityToken(
                issuer: _tokenOptions.Issuer,
                audience: _tokenOptions.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(_tokenOptions.Expiration),
                signingCredentials: _tokenOptions.SigningCredentials);
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        public string NonceGenerator(string extra = "")
        {
            string result = "";
            SHA1 sha1 = SHA1.Create();

            Random rand = new Random();

            while (result.Length < 32)
            {
                string[] generatedRandoms = new string[4];

                for (int i = 0; i < 4; i++)
                {
                    generatedRandoms[i] = rand.Next().ToString();
                }

                result += Convert.ToBase64String(sha1.ComputeHash(Encoding.ASCII.GetBytes(string.Join("", generatedRandoms) + "|" + extra))).Replace("=", "").Replace("/", "").Replace("+", "");
            }

            return result.Substring(0, 32);
        }

        /// <summary>
        /// Auth by JSON Body
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth")]
        public Task<APIResponse<AuthResponse>> PostFromBody([FromBody] AuthRequest req)
        {
            return Auth(req);
        }

        /// <summary>
        /// Auth by Form POST
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth/form")]
        public Task<APIResponse<AuthResponse>> PostFromForm([FromForm] AuthRequest req)
        {
            return Auth(req);
        }
    }

}
