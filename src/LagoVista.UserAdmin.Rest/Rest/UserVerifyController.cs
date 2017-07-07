using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Managers;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.UserAdmin.ViewModels.VerifyIdentity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using LagoVista.UserAdmin.Models.DTOs;
using System.Threading.Tasks;
using LagoVista.UserAdmin.Resources;
using System;

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class UserVerifyController : LagoVistaBaseController
    {
        private readonly IAppUserManager _appUserManager;
        private readonly IOrganizationManager _orgManager;
        private readonly IEmailSender _emailSender;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly ISmsSender _smsSender;
        private readonly UserManager<AppUser> _userManager;
        private readonly IAdminLogger _adminLogger;
        /* 
         * Note this MUCH match the name of the action on the VerifyIdentityController in the Web project
         * this should likely all be refactored into the User Admin project, but not today....KDW 7/4/2017
         */
        private const string ConfirmEmailLink = "ConfirmEmailLink";


        public UserVerifyController(IAppUserManager appUserManager, IOrganizationManager orgManager, IEmailSender emailSender, ISmsSender smsSender, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IAdminLogger logger) : base(userManager, logger)
        {
            _appUserManager = appUserManager;
            _orgManager = orgManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _adminLogger = Logger;
        }

        /// <summary>
        /// Verify User Opened Email
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/checkemailconfirmed")]
        public async Task<InvokeResult> CheckConfirmedAsync()
        {
            if (User == null || !User.Identity.IsAuthenticated)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "User Not Logged In, Not Available.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            var user = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            if (user == null)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "Could not get current user.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            if (user.EmailConfirmed)
            {
                return InvokeResult.Success;
            }
            else
            {
                return InvokeResult.FromErrors(new ErrorMessage() { Message = "Email Not Confirmed" });
            }
        }

        /// <summary>
        /// Verify User - Send Confirmation Email
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/sendconfirmationemail")]
        public async Task<InvokeResult> SendConfirmationEmailAsync()
        {
            if (User == null || !User.Identity.IsAuthenticated)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "User Not Logged In, Not Available.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            var user = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            if (user == null)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "Could not get current user.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            try
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = System.Net.WebUtility.UrlEncode(code);
                var callbackUrl = Url.Action(nameof(ConfirmEmailLink), "VerifyIdentity", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
                var mobileCallbackUrl = Url.Action(nameof(ConfirmEmailLink), "VerifyIdentity", new { userId = user.Id, code = code }, protocol: "nuviot");
                var subject = UserAdminRestResources.Email_Verification_Subject.Replace("[APP_NAME]", UserAdminRestResources.Common_AppName);
                var body = UserAdminRestResources.Email_Verification_Body.Replace("[CALLBACK_URL]", callbackUrl).Replace("[MOBILE_CALLBACK_URL]", mobileCallbackUrl);
                await _emailSender.SendAsync(user.Email, subject, body);

                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Verbose, "UserVerifyController_SendSMSCodeAsync", "SendEmailConfirmation",
                    new System.Collections.Generic.KeyValuePair<string, string>("phone", user.Email));

                return InvokeResult.Success;
            }
            catch (Exception ex)
            {
                _adminLogger.AddException("UserVerifyController_SendConfirmationEmailAsync", ex);
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegErrorSendingEmail.ToErrorMessage(), new ErrorMessage() { Message = ex.Message });
            }
        }

        /// <summary>
        /// Verify User - Send SMS Code
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/verify/sendsmscode")]
        public async Task<InvokeResult> SendSMSCodeAsync([FromBody] VerfiyPhoneNumberDTO verifyPhoneNumberViewModel)
        {
            if (User == null || !User.Identity.IsAuthenticated)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "User Not Logged In, Not Available.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            if (String.IsNullOrEmpty(verifyPhoneNumberViewModel.PhoneNumber))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendSMSCodeAsync", UserAdminErrorCodes.RegMissingEmail.Message);
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegMissingPhoneNumber.ToErrorMessage());
            }

            var user = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            if (user == null)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "Could not get current user.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            try
            {
                var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, verifyPhoneNumberViewModel.PhoneNumber);
                await _smsSender.SendAsync(verifyPhoneNumberViewModel.PhoneNumber, UserAdminRestResources.SMS_Verification_Body.Replace("[CODE]", code).Replace("[APP_NAME]", UserAdminRestResources.Common_AppName));
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Verbose, "UserVerifyController_SendSMSCodeAsync", "SendSMSCode",
                    new System.Collections.Generic.KeyValuePair<string, string>("phone", verifyPhoneNumberViewModel.PhoneNumber),
                    new System.Collections.Generic.KeyValuePair<string, string>("code", code));
                return InvokeResult.Success;
            }
            catch (Exception ex)
            {
                _adminLogger.AddException("UserVerifyController_SendSMSCodeAsync", ex);
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegErrorSendingSMS.ToErrorMessage(), new ErrorMessage() { Message = ex.Message });
            }
        }

        /// <summary>
        /// Verify User - SMS
        /// </summary>
        /// <param name="verifyViewModel"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/sms")]
        public async Task<InvokeResult> ValidateSMSAsync([FromBody] VerfiyPhoneNumberDTO verifyViewModel)
        {
            if (User == null || !User.Identity.IsAuthenticated)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "User Not Logged In, Not Available.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            var user = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            if (user == null)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "Could not get current user.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            var result = await _userManager.ChangePhoneNumberAsync(user, verifyViewModel.PhoneNumber, verifyViewModel.SMSCode);
            if (result.Succeeded)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Verbose, "UserVerifyController_ValidateSMSAsync", "SuccessValidatePhone",
                    new System.Collections.Generic.KeyValuePair<string, string>("phone", verifyViewModel.PhoneNumber),
                    new System.Collections.Generic.KeyValuePair<string, string>("code", verifyViewModel.SMSCode));

                return InvokeResult.Success;
            }
            else
            {
                var couldNotVerifyResult = new InvokeResult();
                couldNotVerifyResult.Errors.Add(new ErrorMessage(UserAdminRestResources.SMS_CouldNotVerify));
                return couldNotVerifyResult;
            }
        }

    }
}
