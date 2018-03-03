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
using LagoVista.Core.Validation;
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.UserAdmin.Managers;
using LagoVista.AspNetCore.Identity.Managers;
using LagoVista.Core.Interfaces;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Resources;
using System.Text.RegularExpressions;
using LagoVista.IoT.Logging.Exceptions;
using System.Net;
using System.Collections.Generic;
using LagoVista.UserAdmin.ViewModels.Users;

namespace LagoVista.UserAdmin.Rest
{


    /// <summary>
    /// Authentication Services
    /// </summary>
    [AllowAnonymous]
    public class AuthServices : LagoVistaBaseController
    {
        private readonly IAuthTokenManager _tokenManager;
        private readonly IPasswordManager _passwordMangaer;
        private readonly SignInManager<AppUser> _signInManager;


        //IMPORTANT Until this can all be refactored into the UserAdmin class this NEEDS to point to action on the Web Site.
        public const string ACTION_RESET_PASSWORD = "/Account/ResetPassword";

        public AuthServices(IAuthTokenManager tokenManager, IPasswordManager passwordManager, IAdminLogger logger, IAppUserManager appUserManager, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IEmailSender emailSender, IAppConfig appConfig) : base(userManager, logger)
        {
            _tokenManager = tokenManager;
            _passwordMangaer = passwordManager;
            _signInManager = signInManager;
            
        }

        private Task<InvokeResult<AuthResponse>> HandleAuthRequest(AuthRequest req)
        {
            if (req.GrantType == AuthTokenManager.GRANT_TYPE_PASSWORD)
            {
                return _tokenManager.AccessTokenGrantAsync(req);
            }
            else if (req.GrantType == AuthTokenManager.GRANT_TYPE_REFRESHTOKEN)
            {
                return _tokenManager.RefreshTokenGrantAsync(req);
            }
            else if(String.IsNullOrEmpty(req.GrantType))
            {
                throw new Exception($"Missing Grant Type.");
            }
            else
            {
                throw new Exception($"Invalid Grant Type - [{req.GrantType}]");
            }
        }

        /// <summary>
        /// Auth by JSON Body
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth")]
        [AllowAnonymous]
        public Task<InvokeResult<AuthResponse>> AuthFromBody([FromBody] AuthRequest req)
        {
            return HandleAuthRequest(req);               
        }

        /// <summary>
        /// Auth by Form POST
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth/form")]
        [AllowAnonymous]
        public Task<InvokeResult<AuthResponse>> AuthFromForm([FromForm] AuthRequest req)
        {
            return HandleAuthRequest(req);
        }

        /// <summary>
        /// Auth by Form Post with Simple Email Address and Password, will set cookie rather than JWT
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/login")]
        public async Task<InvokeResult> CookieAuthFromForm([FromForm] LoginViewModel model)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return InvokeResult.Success;
            }
            else
            {
                return InvokeResult.FromError("Could not authenticate");
            }
        }

        /// <summary>
        /// User Service - Send Reset Password Link
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/auth/resetpassword/sendlink")]
        [AllowAnonymous]
        public Task<InvokeResult> SendResetPasswordLinkAsync([FromBody] SendResetPasswordLink sendResetPasswordLink)
        {
            return _passwordMangaer.SendResetPasswordLinkAsync(sendResetPasswordLink);
        }

        /// <summary>
        /// User Service - Reset Password
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/auth/resetpassword")]
        [AllowAnonymous]
        public Task<InvokeResult> ResetPasswordAsync([FromBody] ResetPassword resetPassword)
        {
            return _passwordMangaer.ResetPasswordAsync(resetPassword);
        }

        /// <summary>
        /// User Service - Change Password
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/auth/changepassword")]
        [Authorize]
        public Task<InvokeResult> ChangePasswordAsync([FromBody] ChangePassword changePassword)
        {
            return _passwordMangaer.ChangePasswordAsync(changePassword, OrgEntityHeader, UserEntityHeader);
        }
    }
}
