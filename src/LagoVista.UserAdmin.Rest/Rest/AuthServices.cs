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
using LagoVista.IoT.Logging.Loggers;
using LagoVista.UserAdmin.Interfaces.Repos.Security;

namespace LagoVista.UserAdmin.Rest
{
    /// <summary>
    /// Authentication Services
    /// </summary>
    [AllowAnonymous]
    public class AuthServices : LagoVistaBaseController
    {
        IAuthTokenManager _tokenManage;

        public AuthServices(IAuthTokenManager tokenManager, IAdminLogger logger, UserManager<AppUser> userManager) : base(userManager, logger)
        {
            _tokenManage = tokenManager;
        }
        
        /// <summary>
        /// Auth by JSON Body
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth")]
        public async Task<APIResponse<AuthResponse>> PostFromBody([FromBody] AuthRequest req)
        {
            var response = await _tokenManage.AuthAsync(req, OrgEntityHeader, UserEntityHeader);
            return APIResponse<AuthResponse>.Create(response);
        }

        /// <summary>
        /// Auth by Form POST
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth/form")]
        public async Task<APIResponse<AuthResponse>> PostFromForm([FromForm] AuthRequest req)
        {
            var response = await _tokenManage.AuthAsync(req, OrgEntityHeader, UserEntityHeader);

            return APIResponse<AuthResponse>.Create(response);
        }
    }

}
