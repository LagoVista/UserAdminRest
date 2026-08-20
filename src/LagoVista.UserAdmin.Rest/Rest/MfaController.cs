// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: 4e3f1c9b8a7d6c5b4a3f2e1d0c9b8a7d6c5b4a3f2e1d0c9b8a7d6c5b4a3f2e1d
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.Core.Models;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Authentication;
using LagoVista.UserAdmin.Authentication.Flows;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [ConfirmedUser]
    public class MfaController : LagoVistaBaseController
    {
        private readonly IAppUserMfaManager _mfaManager;
        private readonly IAuthenticationFlowService _authFlowService;
        private readonly ITotpAdministrativeResetService _administrativeResetService;

        public MfaController(IAppUserMfaManager mfaManager, IAuthenticationFlowService authFlowService, ITotpAdministrativeResetService administrativeResetService, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _mfaManager = mfaManager ?? throw new ArgumentNullException(nameof(mfaManager));
            _authFlowService = authFlowService ?? throw new ArgumentNullException(nameof(authFlowService));
            _administrativeResetService = administrativeResetService ?? throw new ArgumentNullException(nameof(administrativeResetService));
        }

        /* ============================
         * Enrollment
         * ============================ */

        [HttpPost("/api/auth/mfatotp/enrollment/begin")]
        public Task<InvokeResult<AppUserTotpEnrollmentInfo>> BeginTotpEnrollmentAsync()
        {
            return _authFlowService.BeginTotpEnrollmentAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }

        public class AppUserTotpSecret
        {
            public string Totp { get; set; }
        }

        [HttpPost("/api/auth/mfatotp/enrollment/confirm")]
        public Task<InvokeResult<List<string>>> ConfirmTotpEnrollmentAsync([FromBody] AppUserTotpSecret totpSecret)
        {
            return _authFlowService.ConfirmTotpEnrollmentAsync(UserEntityHeader.Id, totpSecret.Totp, OrgEntityHeader, UserEntityHeader);
        }

        public class AppUserTotpPost
        {
            public string Totp { get; set; }
        }

        /* ============================
         * Verification (authenticated step-up)
         * ============================ */

        [HttpPost("/api/auth/mfatotp/verify")]
        public Task<InvokeResult> VerifyTotpAsync([FromQuery] bool stepUp, [FromBody] AppUserTotpPost totpPost)
        {
            return _mfaManager.VerifyTotpAsync(UserEntityHeader.Id, totpPost.Totp, stepUp, OrgEntityHeader, UserEntityHeader);
        }

        /* ============================
         * Recovery codes
         * ============================ */

        [HttpPost("/api/auth/mfarecovery/rotate")]
        public Task<InvokeResult<List<string>>> RotateRecoveryCodesAsync()
        {
            return _authFlowService.RotateTotpRecoveryCodesAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }

        public class RecoveryCodePost
        {
            public string RecoveryCode { get; set; }
        }

        [HttpPost("/api/auth/mfarecovery/consume")]
        public Task<InvokeResult> ConsumeRecoveryCodeAsync([FromQuery] bool stepUp, [FromBody] RecoveryCodePost recoveryCodePost)
        {
            return _mfaManager.ConsumeRecoveryCodeAsync(UserEntityHeader.Id, recoveryCodePost.RecoveryCode, stepUp, OrgEntityHeader, UserEntityHeader);
        }

        /* ============================
         * Reset / disable
         * ============================ */

        [HttpPost("/api/auth/mfadisable")]
        public Task<InvokeResult> DisableMfaAsync()
        {
            return _authFlowService.TurnOffTotpAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/api/auth/mfareset")]
        public Task<InvokeResult> ResetMfaAsync()
        {
            return _mfaManager.ResetMfaAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/api/auth/mfa/totp/admin-reset/{targetUserId}")]
        public Task<InvokeResult> AdministrativelyResetTotpAsync(string targetUserId)
        {
            return _administrativeResetService.ResetAsync(targetUserId, OrgEntityHeader, UserEntityHeader);
        }
    }
}
