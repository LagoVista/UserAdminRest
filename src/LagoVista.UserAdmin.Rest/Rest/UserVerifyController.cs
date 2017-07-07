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
        public InvokeResult CheckConfirmedAsync()
        {
            return InvokeResult.Success;
        }

        /// <summary>
        /// Verify User - Send Confirmation Email
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/sendconfirmationemail")]
        public async Task<InvokeResult> SendConfirmationEmailAsync()
        {
            try
            {
                var user = await GetCurrentUserAsync();
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = System.Net.WebUtility.UrlEncode(code);
                var callbackUrl = Url.Action(nameof(ConfirmEmailLink), "VerifyIdentity", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
                var mobileCallbackUrl = Url.Action(nameof(ConfirmEmailLink), "VerifyIdentity", new { userId = user.Id, code = code }, protocol: "nuviot");
                var subject = UserAdminRestResources.Email_Verification_Subject.Replace("[APP_NAME]", UserAdminRestResources.Common_AppName);
                var body = UserAdminRestResources.Email_Verification_Body.Replace("[CALLBACK_URL]", callbackUrl).Replace("[MOBILE_CALLBACK_URL]", mobileCallbackUrl);
                await _emailSender.SendAsync(user.Email, subject, body);

                return InvokeResult.Success;
            }
            catch (Exception ex)
            {
                _adminLogger.AddException("UserVerifyController_SendConfirmationEmailAsync", ex);
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegErrorSendingEmail.ToErrorMessage());
            }
        }

        /// <summary>
        /// Verify User - Send SMS Code
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/sendsmscode")]
        public async Task<InvokeResult> SendSMSCodeAsync([FromBody] VerfiyPhoneNumberDTO verifyPhoneNumberViewModel)
        {
            if (String.IsNullOrEmpty(verifyPhoneNumberViewModel.PhoneNumber))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserVerifyController_SendSMSCodeAsync", UserAdminErrorCodes.RegMissingEmail.Message);
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegMissingPhoneNumber.ToErrorMessage());
            }

            try
            {
                var user = await GetCurrentUserAsync();
                var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, verifyPhoneNumberViewModel.PhoneNumber);
                ViewData["code"] = code;
                await _smsSender.SendAsync(verifyPhoneNumberViewModel.PhoneNumber, UserAdminRestResources.SMS_Verification_Body.Replace("[CODE]", code).Replace("[APP_NAME]", UserAdminRestResources.Common_AppName));

                return InvokeResult.Success;
            }
            catch (Exception ex)
            {
                _adminLogger.AddException("UserVerifyController_SendSMSCodeAsync", ex);
                return InvokeResult.FromErrors(UserAdminErrorCodes.RegErrorSendingSMS.ToErrorMessage());
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
            var user = await GetCurrentUserAsync();
            var result = await _userManager.ChangePhoneNumberAsync(user, verifyViewModel.PhoneNumber, verifyViewModel.SMSCode);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                await _signInManager.SignInAsync(user, false);
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
