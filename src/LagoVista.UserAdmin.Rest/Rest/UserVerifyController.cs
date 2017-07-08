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
using LagoVista.Core.Interfaces;

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
        private readonly IAppConfig _appConfig;


        /* 
         * Note this MUCH match the name of the action on the VerifyIdentityController in the Web project
         * this should likely all be refactored into the User Admin project, but not today....KDW 7/4/2017
         */
        private const string ConfirmEmailLink = "ConfirmEmailLink";


        public UserVerifyController(IAppUserManager appUserManager, IOrganizationManager orgManager, IEmailSender emailSender, 
                                ISmsSender smsSender, UserManager<AppUser> userManager,
                                SignInManager<AppUser> signInManager, IAdminLogger logger, IAppConfig appConfig) : base(userManager, logger)
        {
            _appUserManager = appUserManager;
            _orgManager = orgManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _adminLogger = Logger;
            _appConfig = appConfig;
        }

        /// <summary>
        /// Verify User - Is Email Confirmed
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/isemailconfirmed")]
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
                var callbackUrl =   $"{_appConfig.WebAddress}/VerifyIdentity/{ConfirmEmailLink}?userId={user.Id}&code={code}";
                var mobileCallbackUrl = $"nuviot://confirmemail?userId={user.Id}&code={code}";
                Console.WriteLine(callbackUrl);
                Console.WriteLine(mobileCallbackUrl);

                var subject = UserAdminRestResources.Email_Verification_Subject.Replace("[APP_NAME]", _appConfig.AppName);
                var body = UserAdminRestResources.Email_Verification_Body.Replace("[CALLBACK_URL]", callbackUrl).Replace("[MOBILE_CALLBACK_URL]", mobileCallbackUrl);

                Console.WriteLine(body);

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
        /// Verify User - Send Confirmation SMS Code
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/verify/sendsmscode")]
        public async Task<InvokeResult> SendSMSCodeAsync([FromBody] VerfiyPhoneNumberDTO sendSMSCode)
        {
            if (User == null || !User.Identity.IsAuthenticated)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendSMSCodeAsync", "User Not Logged In, Not Available.");
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
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendSMSCodeAsync", "Could not get current user.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            try
            {
                var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, sendSMSCode.PhoneNumber);
                var result = await _smsSender.SendAsync(sendSMSCode.PhoneNumber, UserAdminRestResources.SMS_Verification_Body.Replace("[CODE]", code).Replace("[APP_NAME]", _appConfig.AppName));

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
        /// Verify User - Confirm SMS
        /// </summary>
        /// <param name="verifyRequest"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/sms")]
        public async Task<InvokeResult> ValidateSMSAsync([FromBody] VerfiyPhoneNumberDTO verifyRequest)
        {
            if (User == null || !User.Identity.IsAuthenticated)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_ValidateSMSAsync", "User Not Logged In, Not Available.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            var user = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            if (user == null)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_ValidateSMSAsync", "Could not get current user.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            var result = await _userManager.ChangePhoneNumberAsync(user, verifyRequest.PhoneNumber, verifyRequest.SMSCode);
            if (result.Succeeded)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Verbose, "UserVerifyController_ValidateSMSAsync", "Success_ConfirmSMS",
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

        /// <summary>
        /// Verify User - Confirm Email
        /// </summary>
        /// <param name="confirmemaildto"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/email")]
        public async Task<InvokeResult> ValidateEmailAsync([FromBody] ConfirmEmailDTO confirmemaildto)
        {
            if (User == null || !User.Identity.IsAuthenticated)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_ValidateEmailAsync", "User Not Logged In, Not Available.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            var user = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            if (user == null)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_ValidateEmailAsync", "Could not get current user.");
                return InvokeResult.FromErrors(UserAdminErrorCodes.AuthCouldNotFindUserAccount.ToErrorMessage());
            }

            var code = System.Net.WebUtility.UrlDecode(confirmemaildto.ReceivedCode);
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Verbose, "UserVerifyController_ValidateEmailAsync", "Success_ConfirmEmail",
                    new KeyValuePair<string, string>("toEmail", user.Email),
                    new KeyValuePair<string, string>("code", confirmemaildto.ReceivedCode));

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

                errs.Add(new KeyValuePair<string, string>("toEmail", user.Email));
                errs.Add(new KeyValuePair<string, string>("code", confirmemaildto.ReceivedCode));

                _adminLogger.AddError("UserVerifyController_ValidateEmailAsync", "Failed", errs.ToArray());

                couldNotVerifyResult.Errors.Add(new ErrorMessage(UserAdminRestResources.SMS_CouldNotVerify));
                return couldNotVerifyResult;
            }
        }

    }
}
