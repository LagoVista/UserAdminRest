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

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class UserVerifyController : LagoVistaBaseController
    {
        IUserVerficationManager _userVerificationManager;
        UserManager<AppUser> _userManager;
        IAdminLogger _adminLogger;

        public UserVerifyController(IUserVerficationManager userVerificationManager, IAdminLogger logger, UserManager<AppUser> userManager, IAppConfig appConfig) : base(userManager, logger)
        {
            _userVerificationManager = userVerificationManager;
            _adminLogger = logger;
            _userManager = userManager;
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

        /// <summary>
        /// Verify User - Send Confirmation Email
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/email/confirmationcode/send")]
        public Task<InvokeResult<string>> SendConfirmationEmailAsync()
        {
            return _userVerificationManager.SendConfirmationEmailAsync(UserEntityHeader);
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
            code = System.Net.WebUtility.UrlDecode(code);

            _adminLogger.Trace($"[UserVerifyController__ValidateEmailAsync] User: {userid} Code: {code}");

            if (string.IsNullOrEmpty(userid))
                return Redirect($"{CommonLinks.CouldNotConfirmEmail}?err=userid is a required field");

            _adminLogger.Trace($"[UserVerifyController__ValidateEmailAsync_1] User: {userid} Code: {code}");

            if (string.IsNullOrEmpty(code))
                return Redirect($"{CommonLinks.CouldNotConfirmEmail}?err=code is a required field");

            _adminLogger.Trace($"[UserVerifyController__ValidateEmailAsync_2] User: {userid} Code: {code}");

            var user = await _userManager.FindByIdAsync(userid);
            if (user == null)
                return Redirect($"{CommonLinks.CouldNotConfirmEmail}?err=could not find user");

            _adminLogger.Trace($"[UserVerifyController__ValidateEmailAsync_3] User: {user.Name} Code: {code}");

            var result = await _userVerificationManager.ValidateEmailAsync(new ConfirmEmail() {  ReceivedCode = code}, user.ToEntityHeader());
            if (result.Successful)
                return Redirect(CommonLinks.EmailConfirmed);

            return Redirect(CommonLinks.CouldNotConfirmEmail);
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
