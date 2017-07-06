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
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

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

        /* 
         * Note this MUCH match the name of the action on the VerifyIdentityController in the Web project
         * this should likely all be refactored into the User Admin project, but not today....KDW 7/4/2017
         */
        private const string ConfirmEmailLink = "ConfirmEmailLink";


        public UserVerifyController(IAppUserManager appUserManager, IOrganizationManager orgManager, ISmsSender smsSender, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IAdminLogger logger) : base(userManager, logger)
        {
            _appUserManager = appUserManager;
            _orgManager = orgManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _smsSender = smsSender;
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

        /// <summary>
        /// Verify User - Send SMS Code
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/sendsmscode")]
        public async Task<InvokeResult> SendSMSCode([FromBody] VerifyPhoneNumberViewModel verifyPhoneNumberViewModel)
        {
            var user = await GetCurrentUserAsync();
            var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, verifyPhoneNumberViewModel.PhoneNumber);
            ViewData["code"] = code;
            await _smsSender.SendAsync(verifyPhoneNumberViewModel.PhoneNumber, UserAdminRestResources.SMS_Verification_Body.Replace("[CODE]", code).Replace("[APP_NAME]", UserAdminRestResources.Common_AppName));

            return InvokeResult.Success;
        }

        /// <summary>
        /// Verify User - SMS
        /// </summary>
        /// <param name="verifyViewModel"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/sms")]
        public async Task<InvokeResult> ValidateSMSAsync([FromBody] VerifyPhoneNumberViewModel verifyViewModel)
        {
            var user = await GetCurrentUserAsync();
            var result = await _userManager.ChangePhoneNumberAsync(user, verifyViewModel.PhoneNumber, verifyViewModel.Code);
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
