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
using System.Collections.Generic;

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
                var result = await _emailSender.SendAsync(user.Email, subject, body);

                _adminLogger.LogInvokeResult("UserVerifyController_SendConfirmationEmailAsync", result,
                    new System.Collections.Generic.KeyValuePair<string, string>("toAddress", user.Email));

                return result;
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
        public async Task<InvokeResult> SendSMSCodeAsync([FromBody] VerfiyPhoneNumberDTO sendSMSCode)
        {
            if (User == null || !User.Identity.IsAuthenticated)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendConfirmationEmailAsync", "User Not Logged In, Not Available.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            if (String.IsNullOrEmpty(sendSMSCode.PhoneNumber))
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
                var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, sendSMSCode.PhoneNumber);
                var result = await _smsSender.SendAsync(sendSMSCode.PhoneNumber, UserAdminRestResources.SMS_Verification_Body.Replace("[CODE]", code).Replace("[APP_NAME]", UserAdminRestResources.Common_AppName));

                _adminLogger.LogInvokeResult("UserVerifyController_SendSMSCodeAsync", result, 
                    new KeyValuePair<string, string>("phone", sendSMSCode.PhoneNumber),
                    new KeyValuePair<string, string>("code", code));

                return result;
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
        /// <param name="verifyRequest"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/sms")]
        public async Task<InvokeResult> ValidateSMSAsync([FromBody] VerfiyPhoneNumberDTO verifyRequest)
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

            var result = await _userManager.ChangePhoneNumberAsync(user, verifyRequest.PhoneNumber, verifyRequest.SMSCode);
            if (result.Succeeded)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Verbose,"UserVerifyController_ValidateSMSAsync", "Success",
                    new KeyValuePair<string, string>("phone", verifyRequest.PhoneNumber),
                    new KeyValuePair<string, string>("code", verifyRequest.SMSCode));

                return InvokeResult.Success;
            }
            else
            {
                var couldNotVerifyResult = new InvokeResult();

                var errs = new List<KeyValuePair<string, string>>();
                var idx = 1;
                foreach (var identityError in result.Errors)
                {
                    errs.Add(new KeyValuePair<string, string>($"Err{idx++}", $"{identityError.Code} - {identityError.Description}"));
                    couldNotVerifyResult.Errors.Add(new ErrorMessage(identityError.Code, identityError.Description));
                }

                errs.Add(new KeyValuePair<string, string>("phone", verifyRequest.PhoneNumber));
                errs.Add(new KeyValuePair<string, string>("code", verifyRequest.SMSCode));

                _adminLogger.AddError("UserVerifyController_ValidateSMSAsync", "Failed", errs.ToArray());

                couldNotVerifyResult.Errors.Add(new ErrorMessage(UserAdminRestResources.SMS_CouldNotVerify));
                return couldNotVerifyResult;
            }
        }

    }
}
