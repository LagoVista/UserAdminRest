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

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class UserVerifyController : LagoVistaBaseController
    {
        IUserVerficationManager _userVerificationManager;

        public UserVerifyController(IUserVerficationManager userVerificationManager, IAdminLogger logger, UserManager<AppUser> userManager) : base(userManager, logger)
        {
            _userVerificationManager = userVerificationManager;
        }

        /// <summary>
        /// Verify User - Is Email Confirmed
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/isemailconfirmed")]
        public Task<InvokeResult> CheckConfirmedAsync()
        {
            return _userVerificationManager.CheckConfirmedAsync(OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Verify User - Send Confirmation Email
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/verify/sendconfirmationemail")]
        public Task<InvokeResult> SendConfirmationEmailAsync()
        {
            return _userVerificationManager.SendConfirmationEmailAsync(OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Verify User - Send Confirmation SMS Code
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/verify/sendsmscode")]
        public Task<InvokeResult> SendSMSCodeAsync([FromBody] VerfiyPhoneNumber sendSMSCode)
        {
            return _userVerificationManager.SendSMSCodeAsync(sendSMSCode, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Verify User - Confirm SMS
        /// </summary>
        /// <param name="verifyRequest"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/sms")]
        public Task<InvokeResult> ValidateSMSAsync([FromBody] VerfiyPhoneNumber verifyRequest)
        {
            return _userVerificationManager.ValidateSMSAsync(verifyRequest, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Verify User - Confirm Email
        /// </summary>
        /// <param name="confirmEmail"></param>
        /// <returns></returns>
        [HttpPost("/api/verify/email")]
        public Task<InvokeResult> ValidateEmailAsync([FromBody] ConfirmEmail confirmEmail)
        {
            return _userVerificationManager.ValidateEmailAsync(confirmEmail, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Verify User - skip step to verify phone number.
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/sms/setverified")]
        public Task<InvokeResult> SetUserSMSVerifiedAsync()
        {
            return _userVerificationManager.SetUserSMSValidated(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
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
            return _userVerificationManager.SetUserSMSValidated(userId, OrgEntityHeader, UserEntityHeader);
        }
    }
}
