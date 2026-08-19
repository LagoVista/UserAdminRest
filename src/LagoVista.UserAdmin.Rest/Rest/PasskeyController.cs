// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: a21c7b6b2d8c8b3f6c3f98fd12b4baf3b4b9b3f7b2a1c9f0e7d6a5b4c3d2e1f0
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.AspNetCore.Identity.Interfaces;
using LagoVista.Core;
using LagoVista.Core.Authentication.Models;
using LagoVista.Core.Models;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Authentication;
using LagoVista.UserAdmin.Models.Auth.Passkeys;
using LagoVista.UserAdmin.Models.Security.Passkeys;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    public class PasskeyController : LagoVistaBaseController
    {
        private readonly IAppUserPasskeyManager _passkeyManager;
        private readonly IAuthenticationFlowService _authenticationFlowService;

        public PasskeyController(
            IAppUserPasskeyManager passkeyManager,
            IAuthenticationFlowService authenticationFlowService,
            UserManager<AppUser> userManager,
            IAdminLogger logger) : base(userManager, logger)
        {
            _passkeyManager = passkeyManager ?? throw new ArgumentNullException(nameof(passkeyManager));
            _authenticationFlowService = authenticationFlowService ?? throw new ArgumentNullException(nameof(authenticationFlowService));
        }

        /* ============================
         * User-bound registration
         * ============================ */

        [HttpPost("/api/auth/passkey/registration/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginRegistrationAsync([FromQuery] string passkeyUrl = null)
        {
            return _passkeyManager.BeginRegistrationOptionsAsync(UserEntityHeader.Id, passkeyUrl, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/api/auth/passkey/registration/complete")]
        public Task<InvokeResult> CompleteRegistrationAsync([FromBody] PasskeyRegistrationCompleteRequest request)
        {
            return _passkeyManager.CompleteRegistrationAsync(UserEntityHeader.Id, request, OrgEntityHeader, UserEntityHeader);
        }

        /* ============================
         * User-bound authentication
         * ============================ */

        [HttpPost("/api/auth/passkey/authentication/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginAuthenticationAsync([FromQuery] bool stepUp = false, [FromQuery] string passkeyUrl = null)
        {
            return _passkeyManager.BeginAuthenticationOptionsAsync(UserEntityHeader.Id, stepUp, passkeyUrl, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/api/auth/passkey/authentication/complete")]
        public Task<InvokeResult> CompleteAuthenticationAsync([FromQuery] bool stepUp, [FromBody] PasskeyAuthenticationCompleteRequest request)
        {
            return _passkeyManager.CompleteAuthenticationAsync(UserEntityHeader.Id, request, stepUp, OrgEntityHeader, UserEntityHeader);
        }

        /* ============================
         * Passwordless registration
         * ============================ */

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/registration/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginPasswordlessRegistrationAsync([FromQuery] string passkeyUrl = null)
        {
            return _passkeyManager.BeginPasswordlessRegistrationOptionsAsync(passkeyUrl, OrgEntityHeader, UserEntityHeader);
        }

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/registration/complete")]
        public Task<InvokeResult<PasskeySignInResult>> CompletePasswordlessRegistrationAsync([FromBody] PasskeyRegistrationCompleteRequest request)
        {
            return _passkeyManager.CompletePasswordlessRegistrationAsync(request, OrgEntityHeader, UserEntityHeader);
        }

        /* ============================
         * Passwordless authentication
         * ============================ */

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/authentication/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginPasswordlessAuthenticationAsync([FromQuery] string passkeyUrl = null)
        {
            return _passkeyManager.BeginPasswordlessAuthenticationOptionsAsync(passkeyUrl, OrgEntityHeader, UserEntityHeader);
        }

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/authentication/complete")]
        public async Task<InvokeResult<PasskeySignInResult>> CompletePasswordlessAuthenticationAsync([FromBody] PasskeyAuthenticationCompleteRequest request)
        {
            var proof = await _passkeyManager.CompletePasswordlessAuthenticationAsync(request, OrgEntityHeader, UserEntityHeader);
            if (!proof.Successful || proof.Result?.User == null)
                return proof;

            var session = await _authenticationFlowService.CompleteProvenUserSessionAsync(proof.Result.User, true);
            if (!session.Successful)
                return InvokeResult<PasskeySignInResult>.FromInvokeResult(session.ToInvokeResult());

            return proof;
        }

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/passwordless/authentication/token")]
        public async Task<InvokeResult<AuthResponse>> CompletePasswordlessAuthenticationTokenAsync([FromBody] PasskeyTokenAuthenticationCompleteRequest request)
        {
            if (request?.Passkey == null || request.Auth == null)
                return InvokeResult<AuthResponse>.FromError("passkey_and_auth_request_required");

            var proof = await _passkeyManager.CompletePasswordlessAuthenticationAsync(request.Passkey, OrgEntityHeader, UserEntityHeader);
            if (!proof.Successful || proof.Result?.User == null)
                return InvokeResult<AuthResponse>.FromInvokeResult(proof.ToInvokeResult());

            return await _authenticationFlowService.CompleteProvenUserTokenAsync(request.Auth, proof.Result.User);
        }

        /* ============================
         * Passkey management
         * ============================ */

        [HttpGet("/api/auth/passkey")]
        public Task<InvokeResult<PasskeyCredentialSummary[]>> ListPasskeysAsync()
        {
            return _passkeyManager.ListPasskeysAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPut("/api/auth/passkey/{credentialId}/rename")]
        public Task<InvokeResult> RenamePasskeyAsync(string credentialId, [FromQuery] string name)
        {
            return _passkeyManager.RenamePasskeyAsync(UserEntityHeader.Id, credentialId, name, OrgEntityHeader, UserEntityHeader);
        }

        [HttpDelete("/api/auth/passkey/{credentialId}")]
        public Task<InvokeResult> RemovePasskeyAsync(string credentialId)
        {
            return _passkeyManager.RemovePasskeyAsync(UserEntityHeader.Id, credentialId, OrgEntityHeader, UserEntityHeader);
        }
    }
}
