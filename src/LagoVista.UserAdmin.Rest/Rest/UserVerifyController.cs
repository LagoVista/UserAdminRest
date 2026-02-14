// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: 50823cabe203ddef93c92eb84ae7c400903c22dd7877f22cd2b58069ecdbaaed
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.Core.Validation;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using LagoVista.UserAdmin.Models.DTOs;
using System.Threading.Tasks;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using Twilio.Types;
using LagoVista.Core.Interfaces;
using System;
using LagoVista.UserAdmin.Managers;

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class UserVerifyController : LagoVistaBaseController
    {
        IUserVerficationManager _userVerificationManager;
        UserManager<AppUser> _userManager;
        IAppUserManager _appusermanager;
        IAdminLogger _adminLogger;

        public UserVerifyController(IUserVerficationManager userVerificationManager, IAdminLogger logger, IAppUserManager appUserManager, UserManager<AppUser> userManager, IAppConfig appConfig) : base(userManager, logger)
        {
            _userVerificationManager = userVerificationManager;
            _adminLogger = logger;
            _userManager = userManager;
            _appusermanager = appUserManager ?? throw new ArgumentNullException(nameof(appUserManager));
        }

        /// <summary>
        /// Verify User - Is Email Confirmed
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/isemailconfirmed")]
        public Task<InvokeResult> CheckConfirmedAsync()
        {
            return _userVerificationManager.CheckConfirmedAsync(UserEntityHeader);
        }

        [SystemAdmin]
        [HttpGet("/api/verify/{userid}/email/confirmationcode/send")]
        public Task<InvokeResult<string>> SendConfirmationEmailAsync(string userid)
        {
            return _userVerificationManager.SendConfirmationEmailAsync(userid);
        }
        /// <summary>
        /// Verify User - Send Confirmation Email
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/email/confirmationcode/send")]
        public Task<InvokeResult<string>> SendConfirmationEmailAsync()
        {
            return _userVerificationManager.SendConfirmationEmailAsync(UserEntityHeader.Id);
        }

        /// <summary>
        /// Verify User - Send Confirmation SMS Code
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/verify/sendsmscode")]
        public Task<InvokeResult<string>> SendSMSCodeAsync([FromBody] VerfiyPhoneNumber sendSMSCode)
        {
            return _userVerificationManager.SendSMSCodeAsync(sendSMSCode, UserEntityHeader);
        }

        /// <summary>
        /// Verify User - Send Confirmation SMS Code
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/verify/sendsmscode/{phonenumber}")]
        public Task<InvokeResult<string>> SendSMSCodeAsync(string phonenumber)
        {
            return _userVerificationManager.SendSMSCodeAsync(new VerfiyPhoneNumber(){PhoneNumber= phonenumber}, UserEntityHeader);
        }

        /// <summary>
        /// Verify User - Confirm SMS
        /// </summary>
        /// <param name="verifyRequest"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/sms")]
        public Task<InvokeResult> ValidateSMSAsync([FromBody] VerfiyPhoneNumber verifyRequest)
        {           
            return _userVerificationManager.ValidateSMSAsync(verifyRequest,  UserEntityHeader);
        }

        /// <summary>
        /// Verify User - Confirm Email
        /// </summary>
        /// <param name="confirmEmail"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("/api/verify/email")]
        public Task<InvokeResult> ValidateEmailAsync([FromBody] ConfirmEmail confirmEmail)
        {
            return _userVerificationManager.ValidateEmailAsync(confirmEmail, UserEntityHeader);
        }

        /// <summary>
        /// Verify User - Confirm Email
        /// </summary>
        /// <param name="userid"></param>
        /// <param name="code"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpGet("/api/verify/email")]
        public async Task<IActionResult> ValidateEmailAsync(string userid, string code)
        {
            var user = await _userManager.FindByIdAsync(userid);
            if (user == null)
                return Redirect($"{CommonLinks.CouldNotConfirmEmail}?err=could not find user");

            var result = await _userVerificationManager.ValidateEmailAsync(new ConfirmEmail() {  ReceivedCode = code}, user.ToEntityHeader());
            if (result.Successful)
            {
                if(String.IsNullOrEmpty(result.RedirectURL))
                {
                    return Redirect(CommonLinks.EmailConfirmed);
                }

                return Redirect(result.RedirectURL);
            }

            return Redirect($"{CommonLinks.CouldNotConfirmEmail}?err={result.ErrorMessage}");
        }


        /// <summary>
        /// Verify User - Confirm Email
        /// </summary>
        /// <param name="p"></param>
        /// <param name="c"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpGet("/api/user/verify/email")]
        public async Task<InvokeResult<AppUser>> ValidateEmailAsync2(string p, string c)
        {
            // Not huge security but p is a little different than u for user...
            var code = c;
            var userId = p;
            if(String.IsNullOrWhiteSpace(userId) || String.IsNullOrWhiteSpace(code))
            {
                return InvokeResult<AppUser>.FromError("Sorry, we could not confirm your email address.");
            }
           
            return await _appusermanager.ValidateEmailTokenAsync(userId, code);
        }

        /// <summary>
        /// Verify User - Confirm Phone
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/sms/{code}")]
        public  Task<InvokeResult> ValidatePhoneAsync(string code)
        {
            return _userVerificationManager.ValidateSMSAsync( new VerfiyPhoneNumber() {  SMSCode = code, SkipStep = false },  UserEntityHeader);
        }

        /// <summary>
        /// Verify User - skip step to verify phone number.
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/sms/setverified")]
        public Task<InvokeResult> SetUserSMSVerifiedAsync()
        {
            return _userVerificationManager.SetUserSMSValidated(UserEntityHeader.Id,  UserEntityHeader);
        }
    }

    [SystemAdmin]
    public class UserVerifySettingsController : LagoVistaBaseController
    {
        IUserVerficationManager _userVerificationManager;

        public UserVerifySettingsController(IUserVerficationManager userVerificationManager, IAdminLogger logger, UserManager<AppUser> userManager) : base(userManager, logger)
        {
            _userVerificationManager = userVerificationManager;
        }

        [HttpGet("/api/sysadmin/sms/{userid}/setverified")]
        public Task<InvokeResult> SetUserSMSVerifiedAsync(string userId)
        {
            return _userVerificationManager.SetUserSMSValidated(userId, UserEntityHeader);
        }
    }
}
