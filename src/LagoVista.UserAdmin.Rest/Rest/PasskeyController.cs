// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: a21c7b6b2d8c8b3f6c3f98fd12b4baf3b4b9b3f7b2a1c9f0e7d6a5b4c3d2e1f0
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.Core;
using LagoVista.Core.Models;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers.Passkeys;
using LagoVista.UserAdmin.Models.Security.Passkeys;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [ConfirmedUser]
    public class PasskeyController : LagoVistaBaseController
    {
        private readonly IAppUserPasskeyManager _passkeyManager;

        public PasskeyController(
            IAppUserPasskeyManager passkeyManager,
            UserManager<AppUser> userManager,
            IAdminLogger logger) : base(userManager, logger)
        {
            _passkeyManager = passkeyManager ?? throw new ArgumentNullException(nameof(passkeyManager));
        }

        /* ============================
         * User-bound registration
         * ============================ */

        /// <summary>
        /// Begin passkey registration for the current user
        /// </summary>
        [HttpPost("/api/auth/passkey/registration/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginRegistrationAsync(
            [FromQuery] string passkeyUrl = null)
        {
            return _passkeyManager.BeginRegistrationOptionsAsync(
                UserEntityHeader.Id,
                passkeyUrl,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Complete passkey registration for the current user
        /// </summary>
        [HttpPost("/api/auth/passkey/registration/complete")]
        public Task<InvokeResult> CompleteRegistrationAsync(
            [FromBody] PasskeyRegistrationCompleteRequest request)
        {
            return _passkeyManager.CompleteRegistrationAsync(
                UserEntityHeader.Id,
                request,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /* ============================
         * User-bound authentication
         * ============================ */

        /// <summary>
        /// Begin passkey authentication for the current user
        /// </summary>
        [HttpPost("/api/auth/passkey/authentication/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginAuthenticationAsync(
            [FromQuery] bool stepUp = false,
            [FromQuery] string passkeyUrl = null)
        {
            return _passkeyManager.BeginAuthenticationOptionsAsync(
                UserEntityHeader.Id,
                stepUp,
                passkeyUrl,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Complete passkey authentication for the current user
        /// </summary>
        [HttpPost("/api/auth/passkey/authentication/complete")]
        public Task<InvokeResult> CompleteAuthenticationAsync(
            [FromQuery] bool stepUp,
            [FromBody] PasskeyAuthenticationCompleteRequest request)
        {
            return _passkeyManager.CompleteAuthenticationAsync(
                UserEntityHeader.Id,
                request,
                stepUp,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /* ============================
         * Passwordless registration
         * ============================ */

        /// <summary>
        /// Begin passwordless passkey registration
        /// </summary>
        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/registration/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginPasswordlessRegistrationAsync(
            [FromQuery] string passkeyUrl = null)
        {
            return _passkeyManager.BeginPasswordlessRegistrationOptionsAsync(
                passkeyUrl,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Complete passwordless passkey registration
        /// </summary>
        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/registration/complete")]
        public Task<InvokeResult<PasskeySignInResult>> CompletePasswordlessRegistrationAsync(
            [FromBody] PasskeyRegistrationCompleteRequest request)
        {
            return _passkeyManager.CompletePasswordlessRegistrationAsync(
                request,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /* ============================
         * Passwordless authentication
         * ============================ */

        /// <summary>
        /// Begin passwordless passkey authentication
        /// </summary>
        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/authentication/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginPasswordlessAuthenticationAsync(
            [FromQuery] string passkeyUrl = null)
        {
            return _passkeyManager.BeginPasswordlessAuthenticationOptionsAsync(
                passkeyUrl,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Complete passwordless passkey authentication
        /// </summary>
        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/authentication/complete")]
        public Task<InvokeResult<PasskeySignInResult>> CompletePasswordlessAuthenticationAsync(
            [FromBody] PasskeyAuthenticationCompleteRequest request)
        {
            return _passkeyManager.CompletePasswordlessAuthenticationAsync(
                request,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /* ============================
         * Passkey management
         * ============================ */

        /// <summary>
        /// List passkeys for the current user
        /// </summary>
        [HttpGet("/api/auth/passkey")]
        public Task<InvokeResult<PasskeyCredentialSummary[]>> ListPasskeysAsync()
        {
            return _passkeyManager.ListPasskeysAsync(
                UserEntityHeader.Id,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Rename a passkey
        /// </summary>
        [HttpPut("/api/auth/passkey/{credentialId}/rename")]
        public Task<InvokeResult> RenamePasskeyAsync(
            string credentialId,
            [FromQuery] string name)
        {
            return _passkeyManager.RenamePasskeyAsync(
                UserEntityHeader.Id,
                credentialId,
                name,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Remove a passkey
        /// </summary>
        [HttpDelete("/api/auth/passkey/{credentialId}")]
        public Task<InvokeResult> RemovePasskeyAsync(string credentialId)
        {
            return _passkeyManager.RemovePasskeyAsync(
                 UserEntityHeader.Id,
                credentialId,
                OrgEntityHeader,
                UserEntityHeader);
        }
    }
}
