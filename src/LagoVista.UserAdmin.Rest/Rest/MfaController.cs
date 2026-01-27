// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: 4e3f1c9b8a7d6c5b4a3f2e1d0c9b8a7d6c5b4a3f2e1d0c9b8a7d6c5b4a3f2e1d
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.Core.Models;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
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

        public MfaController(IAppUserMfaManager mfaManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _mfaManager = mfaManager ?? throw new ArgumentNullException(nameof(mfaManager));
        }

        /* ============================
         * Enrollment
         * ============================ */

        /// <summary>
        /// Begin TOTP enrollment for the current user (returns secret + QR payload, etc.)
        /// </summary>
        [HttpPost("/api/auth/mfatotp/enrollment/begin")]
        public Task<InvokeResult<AppUserTotpEnrollmentInfo>> BeginTotpEnrollmentAsync()
        {
            return _mfaManager.BeginTotpEnrollmentAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }

        public class AppUserTotpSecret
        {
            public string Totp { get; set; }
        }


        /// <summary>
        /// Confirm TOTP enrollment for the current user (returns recovery codes)
        /// </summary>
        [HttpPost("/api/auth/mfatotp/enrollment/confirm")]
        public Task<InvokeResult<List<string>>> ConfirmTotpEnrollmentAsync([FromBody] AppUserTotpSecret totpSecret)
        {
            return _mfaManager.ConfirmTotpEnrollmentAsync(UserEntityHeader.Id, totpSecret.Totp, OrgEntityHeader, UserEntityHeader);
        } 

        public class AppUserTotpPost
        {
            public string Totp { get; set; }
        }

        /* ============================
         * Verification (login or step-up)
         * ============================ */

        /// <summary>
        /// Verify TOTP for the current user (login or step-up)
        /// </summary>
        [HttpPost("/api/auth/mfatotp/verify")]
        public Task<InvokeResult> VerifyTotpAsync([FromQuery] bool stepUp, [FromBody] AppUserTotpPost totpPost)
        {
            return _mfaManager.VerifyTotpAsync(UserEntityHeader.Id, totpPost.Totp, stepUp, OrgEntityHeader, UserEntityHeader);
        }

        /* ============================
         * Recovery codes
         * ============================ */

        /// <summary>
        /// Rotate recovery codes for the current user (returns new set)
        /// </summary>
        [HttpPost("/api/auth/mfarecovery/rotate")]
        public Task<InvokeResult<List<string>>> RotateRecoveryCodesAsync()
        {
            return _mfaManager.RotateRecoveryCodesAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }

        public class RecoveryCodePost
        {
            public string RecoveryCode { get; set; }
        }

        /// <summary>
        /// Consume a recovery code for the current user (login or step-up)
        /// </summary>
        [HttpPost("/api/auth/mfarecovery/consume")]
        public Task<InvokeResult> ConsumeRecoveryCodeAsync([FromQuery] bool stepUp, [FromBody] RecoveryCodePost recoveryCodePost)
        {
            return _mfaManager.ConsumeRecoveryCodeAsync(UserEntityHeader.Id, recoveryCodePost.RecoveryCode, stepUp, OrgEntityHeader, UserEntityHeader);
        }   

        /* ============================
         * Reset / disable
         * ============================ */

        /// <summary>
        /// Disable MFA for the current user (turn off 2FA but keep account intact)
        /// </summary>
        [HttpPost("/api/auth/mfadisable")]
        public Task<InvokeResult> DisableMfaAsync()
        {
            return _mfaManager.DisableMfaAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Reset MFA for the current user (force re-enrollment, clears secrets/codes)
        /// </summary>
        [HttpPost("/api/auth/mfareset")]
        public Task<InvokeResult> ResetMfaAsync()
        {
            return _mfaManager.ResetMfaAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }
    }
}
