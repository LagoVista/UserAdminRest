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
using LagoVista.Core.Interfaces;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Resources;
using System.Text.RegularExpressions;
using LagoVista.IoT.Logging.Exceptions;

namespace LagoVista.UserAdmin.Rest
{


    /// <summary>
    /// Authentication Services
    /// </summary>
    [AllowAnonymous]
    public class AuthServices : LagoVistaBaseController
    {
        private readonly IAuthTokenManager _tokenManage;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly IAppUserManager _appUserManager;
        private readonly IAppConfig _appConfig;
        private readonly IEmailSender _emailSender;
        private readonly IAdminLogger _adminLogger;


        //IMPORTANT Until this can all be refactored into the UserAdmin class this NEEDS to point to action on the Web Site.
        public const string ACTION_RESET_PASSWORD = "/Account/ResetPassword";

        public AuthServices(IAuthTokenManager tokenManager, IAdminLogger logger, IAppUserManager appUserManager, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IEmailSender emailSender, IAppConfig appConfig) : base(userManager, logger)
        {
            _tokenManage = tokenManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _appUserManager = appUserManager;
            _appConfig = appConfig;
            _emailSender = emailSender;
            _adminLogger = logger;
        }

        /// <summary>
        /// Auth by JSON Body
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth")]
        public Task<InvokeResult<AuthResponse>> PostFromBody([FromBody] AuthRequest req)
        {
            return _tokenManage.AuthAsync(req, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Auth by Form POST
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth/form")]
        public Task<InvokeResult<AuthResponse>> PostFromForm([FromForm] AuthRequest req)
        {
            return _tokenManage.AuthAsync(req, OrgEntityHeader, UserEntityHeader);
        }


        /// <summary>
        /// User Service - Reset Password
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/auth/resetpassword")]
        public async Task<InvokeResult> SendResetPasswordLinkAsync([FromBody] ResetPasswordDTO resetPasswordDTO)
        {
            if (String.IsNullOrEmpty(resetPasswordDTO.Email))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "AuthServices_SendResetPasswordLinkAsync", UserAdminErrorCodes.RegMissingEmail.Message);
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegMissingEmail.ToErrorMessage());
            }

            var emailRegEx = new Regex(@"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$");
            if (!emailRegEx.Match(resetPasswordDTO.Email).Success)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "AuthServices_SendResetPasswordLinkAsync", UserAdminErrorCodes.RegInvalidEmailAddress.Message);
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegInvalidEmailAddress.ToErrorMessage());
            }

            var appUser = await _userManager.FindByEmailAsync(resetPasswordDTO.Email);
            if (appUser == null)
            {
                _adminLogger.AddError("AuthServices_SendResetPasswordLinkAsync", "CouldNotFindUser", new System.Collections.Generic.KeyValuePair<string, string>("email", resetPasswordDTO.Email));
                return InvokeResult.FromErrors(new ErrorMessage(UserAdminRestResources.Err_ResetPwd_CouldNotFindUser));
            }

            try
            {
                var code = await _userManager.GeneratePasswordResetTokenAsync(appUser);
                var callbackUrl = $"{_appConfig.WebAddress}/{ACTION_RESET_PASSWORD}?code={code}";
                var mobileCallbackUrl = $"nuviot://resetpassword?code={code}";

                var subject = UserAdminRestResources.Email_ResetPassword_Subject.Replace("[APP_NAME]", _appConfig.AppName);
                var body = UserAdminRestResources.Email_ResetPassword_Body.Replace("[CALLBACK_URL]", callbackUrl).Replace("[MOBILE_CALLBACK_URL]", mobileCallbackUrl);

                return await _emailSender.SendAsync(resetPasswordDTO.Email, subject, body);
            }
            catch (Exception ex)
            {
                _adminLogger.AddException("AuthServices_SendResetPasswordLinkAsync", ex);
                return InvokeResult.FromErrors(new ErrorMessage(UserAdminRestResources.Email_RestPassword_ErrorSending), new ErrorMessage() { Message = ex.Message });
            }

        }

        /// <summary>
        /// User Service - Change Password
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/auth/changepassword")]
        public async Task<InvokeResult> ChangePasswordAsync([FromBody] ChangePasswordDTO changePasswordDTO)
        {
            if (String.IsNullOrEmpty(changePasswordDTO.UserId))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "AuthServices_ChangePasswordAsync", "Missing User Id on Change Password Request.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegMissingEmail.ToErrorMessage());
            }

            if (String.IsNullOrEmpty(changePasswordDTO.OldPassword))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "AuthServices_ChangePasswordAsync", "Missing Old Password on Change Password Request.");
                return InvokeResult.FromErrors(new ErrorMessage(UserAdminRestResources.Err_PwdChange_OldPassword_Missing));
            }

            if (String.IsNullOrEmpty(changePasswordDTO.NewPassword))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "AuthServices_ChangePasswordAsync", "Missing Old Password on Change Password Request.");
                return InvokeResult.FromErrors(new ErrorMessage(UserAdminRestResources.Err_PwdChange_NewPassword_Missing));
            }

            //We pass up the user id we think that is logged in, compare it to the one as set in the token
            if (changePasswordDTO.UserId != UserEntityHeader.Id)
            {
                _adminLogger.AddError("AuthServices_ChangePasswordAsync", "UserId Doesn't Match", new System.Collections.Generic.KeyValuePair<string, string>("id", UserEntityHeader.Id));
                return InvokeResult.FromErrors(new ErrorMessage(UserAdminRestResources.Err_UserId_DoesNotMatch));
            }

            var appUser = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            if (appUser == null)
            {
                _adminLogger.AddError("AuthServices_ChangePasswordAsync", "CouldNotFindUser", new System.Collections.Generic.KeyValuePair<string, string>("id", UserEntityHeader.Id));
                return InvokeResult.FromErrors(new ErrorMessage(UserAdminRestResources.Err_PwdChange_CouldNotFindUser));
            }

            var identityResult = await _userManager.ChangePasswordAsync(appUser, changePasswordDTO.OldPassword, changePasswordDTO.NewPassword);
            if (identityResult.Succeeded)
            {
                return InvokeResult.Success;
            }
            else
            {
                var result = new InvokeResult();
                foreach (var err in identityResult.Errors)
                {
                    result.Errors.Add(new ErrorMessage(err.Code, err.Description));
                }

                return result;
            }
        }
    }
}
