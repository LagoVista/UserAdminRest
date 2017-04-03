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
using LagoVista.UserAdmin.Models.Account;
using LagoVista.Core.Authentication.Models;
using LagoVista.Core.Networking.Models;
using LagoVista.AspNetCore.Identity.Models;

namespace LagoVista.UserAdmin.Rest.Rest
{
    /// <summary>
    /// Authentication Services
    /// </summary>
    [Authorize]
    [Route("api/v1/auth")]
    public class AuthServices : LagoVistaBaseController
    {
        private readonly TokenAuthOptions _tokenOptions;
        ILogger _logger;

        private SignInManager<AppUser> _signInManager;
        private UserManager<AppUser> _userManager;


        public AuthServices(TokenAuthOptions tokenOptions, ILogger logger, SignInManager<AppUser> signInManager, UserManager<AppUser> userManager) : base(userManager, logger)
        {
            _tokenOptions = tokenOptions;
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        private async Task<APIResponse<AuthResponse>> Auth(AuthRequest req)
        {
            var result = await _signInManager.PasswordSignInAsync(req.UserName, req.Password, true, false);
            if (result.Succeeded)
            {
                var expires = DateTime.UtcNow.AddDays(_tokenOptions.Expiration.TotalDays);
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var offset = DateTimeOffset.Now;

                var token = GetToken(req.UserName, expires);
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

        private string GetToken(string user, DateTime? expires)
        {
            var handler = new JwtSecurityTokenHandler();

            // Here, you should create or look up an identity for the user which is being authenticated.
            // For now, just creating a simple generic identity.
            var identity = new ClaimsIdentity(new GenericIdentity(user, "TokenAuth"), new[] { new Claim("EntityID", "1", ClaimValueTypes.Integer) });

            var securityToken = handler.CreateToken(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor()
            {
                Issuer = _tokenOptions.Issuer,
                Audience = _tokenOptions.Audience,
                //SigningCredentials = _tokenOptions.SigningCredentials,
                Subject = identity,
                Expires = expires
            });

            return handler.WriteToken(securityToken);
        }

        /// <summary>
        /// Auth by JSON Body
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost]
        public Task<APIResponse<AuthResponse>> PostFromBody([FromBody] AuthRequest req)
        {
            return Auth(req);
        }

        /// <summary>
        /// Auth by Form POST
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("form")]
        public Task<APIResponse<AuthResponse>> PostFromFrom([FromForm] AuthRequest req)
        {
            return Auth(req);
        }
    }
}
