using LagoVista.IoT.Web.Common.Controllers;
using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.Core.Authentication.Models;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.UserAdmin.Interfaces.Repos.Security;
using LagoVista.Core.Validation;
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.UserAdmin.Managers;
using LagoVista.AspNetCore.Identity.Managers;
using LagoVista.Core.Interfaces;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.IoT.Deployment.Admin;
using Prometheus;

namespace LagoVista.UserAdmin.Rest
{


    /// <summary>
    /// Authentication Services
    /// </summary>
    [AllowAnonymous]
    public class AuthServices : LagoVistaBaseController
    {
        public class LoginModel
        {
            public string Email { get; set; }
            public string Password { get; set; }
            public bool RememberMe { get; set; }
        }

        private readonly IAuthTokenManager _tokenManager;
        private readonly IPasswordManager _passwordMangaer;
        private readonly ISignInManager _signInManager;
		private readonly IClientAppManager _clientAppManager;

        protected static readonly Counter UserLogin = Metrics.CreateCounter("nuviot_login", "successful user login.", "source");
        protected static readonly Counter UserLoginFailed = Metrics.CreateCounter("nuviot_login_failed", "unsuccessful user login.", "source", "reason");


        //IMPORTANT Until this can all be refactored into the UserAdmin class this NEEDS to point to action on the Web Site.
        public const string ACTION_RESET_PASSWORD = "/Account/ResetPassword";

        public AuthServices(IAuthTokenManager tokenManager, IPasswordManager passwordManager, IAdminLogger logger, IAppUserManager appUserManager, UserManager<AppUser> userManager, ISignInManager signInManager, IEmailSender emailSender, IAppConfig appConfig, IClientAppManager clientAppManager) : base(userManager, logger)
        {
            _tokenManager = tokenManager;
            _passwordMangaer = passwordManager;
            _signInManager = signInManager;
			_clientAppManager = clientAppManager;
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
            else if(req.GrantType == AuthTokenManager.GRANT_TYPE_SINGLEUSETOKEN)
            {
                return _tokenManager.SingleUseTokenGrantAsync(req);
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
        public async Task<InvokeResult<AuthResponse>> AuthFromBody([FromBody] AuthRequest req)
        {
            var result = await HandleAuthRequest(req);
            if(result.Successful)
                UserLogin.WithLabels("auth-request").Inc();
            else
                UserLoginFailed.WithLabels("auth-request","failed").Inc();

            return result;
        }

        /// <summary>
        /// Auth by JSON Body
        /// </summary>
        /// <param name="req"></param>
        /// <param name="repoId"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth/repo/{repoid}")]
        [AllowAnonymous]
        public async Task<InvokeResult<AuthResponse>> AuthFromBody(String repoId, [FromBody] AuthRequest req)
        {
            req.Email = $"{repoId}-{req.Email}";

            var result = await HandleAuthRequest(req);
            if (result.Successful)
                UserLogin.WithLabels("auth-request-repo").Inc();
            else
                UserLoginFailed.WithLabels("auth-request-repo", "failed").Inc();

            return result;
        }

        /// <summary>
        /// Auth by Form POST
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth/form")]
        [AllowAnonymous]
        public async Task<InvokeResult<AuthResponse>> AuthFromForm([FromForm] AuthRequest req)
        {
            var result = await HandleAuthRequest(req);
            if (result.Successful)
                UserLogin.WithLabels("auth-request-form").Inc();
            else
                UserLoginFailed.WithLabels("auth-request-form", "failed").Inc();

            return result;
        }

        /// <summary>
        /// Auth by Form Post with Simple Email Address and Password, will set cookie rather than JWT
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/login")]
        public async Task<InvokeResult> CookieAuthFromForm([FromBody] LoginModel model)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Successful)
                UserLogin.WithLabels("cookie-auth-request-repo").Inc();
            else
                UserLoginFailed.WithLabels("cookie-auth-request-repo", "failed").Inc();

            return result;
        }

        /// <summary>
        /// Auth by Form Post with Simple Email Address and Password, will set cookie rather than JWT
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/loginkiosk")]
        public async Task<InvokeResult<string>> KioskCookieAuthFromForm([FromForm] LoginModel model)
        {
            if (model != null && !string.IsNullOrEmpty(model.Password))
            {
                var kioskResult = await _clientAppManager.AuthorizeAppAsync(model.Email, model.Password); /* ClientId, ApiKey */
                if (kioskResult.Successful)
                {
                    UserLogin.WithLabels("kiosk").Inc();

                    var clientApp = kioskResult.Result;
      //              var claims = new[]
      //              {
      //                  new Claim(ClaimsFactory.InstanceId, clientApp.DeploymentInstance.Id),
      //                  new Claim(ClaimsFactory.InstanceName, clientApp.DeploymentInstance.Text),
      //                  new Claim(ClaimsFactory.CurrentOrgId, clientApp.OwnerOrganization.Id),
      //                  new Claim(ClaimsFactory.CurrentOrgName, clientApp.OwnerOrganization.Text),
						//new Claim(ClaimsFactory.CurrentUserId, clientApp.ClientAppUser.Id),
      //                  new Claim(ClaimTypes.NameIdentifier, clientApp.ClientAppUser.Text),
      //                  new Claim(ClaimTypes.Surname, "system"),
						//new Claim(ClaimTypes.GivenName, clientApp.ClientAppUser.Text),
      //                  new Claim(ClaimsFactory.KioskId, clientApp.Kiosk.Id),
      //                  new Claim(ClaimsFactory.EmailVerified, true.ToString()),
      //                  new Claim(ClaimsFactory.PhoneVerfiied, true.ToString()),
      //                  new Claim(ClaimsFactory.IsSystemAdmin, false.ToString()),
      //                  new Claim(ClaimsFactory.IsAppBuilder, false.ToString()),
      //                  new Claim(ClaimsFactory.IsOrgAdmin, false.ToString()),
      //                  new Claim(ClaimsFactory.IsPreviewUser, false.ToString()),
      //              };

      //              var identity = new ClaimsIdentity(claims);
                    var clientAppUser = new AppUser(clientApp.ClientAppUser.Id, "system")
                    {
                        Id = clientApp.ClientAppUser.Id,
                        EmailConfirmed = true,
                        PhoneNumberConfirmed = true,
                        IsAppBuilder = false,
                        IsOrgAdmin = false,
                        IsPreviewUser = false,
                        IsSystemAdmin = false,
                        IsUserDevice = false,
                        OwnerUser = clientApp.OwnerUser,
                        UserName = clientApp.ClientAppUser.Id,
						OwnerOrganization = clientApp.OwnerOrganization,
						CurrentOrganization = clientApp.OwnerOrganization,
					};

                    try
                    {
                        await _signInManager.SignInAsync(clientAppUser, false);

                        return InvokeResult<string>.Create(clientApp.Kiosk.Id);
                    }
                    catch
                    {
                        UserLoginFailed.WithLabels("kiosk", "failed").Inc();
                        return InvokeResult<string>.FromError("Could not authenticate (kiosk:1)");
                    }
                }
            }

            UserLoginFailed.WithLabels("kiosk", "failed").Inc();

            return InvokeResult<string>.FromError("Could not authenticate (kiosk:2)");
        }

        /// <summary>
        /// Auth by Form Post with Simple Email Address and Password, will set cookie rather than JWT
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/v1/logoff")]
        public async Task<InvokeResult> Logoff()
        {
            await _signInManager.SignOutAsync();
            return InvokeResult.Success;
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
