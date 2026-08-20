// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: a21c7b6b2d8c8b3f6c3f98fd12b4baf3b4b9b3f7b2a1c9f0e7d6a5b4c3d2e1f0
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.AspNetCore.Identity.Interfaces;
using LagoVista.Core.Authentication.Models;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Authentication;
using LagoVista.UserAdmin.Models.Auth;
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
        private readonly IEmailPasskeyAuthenticationService _emailPasskeyAuthenticationService;
        private readonly IPasskeyMfaAuthenticationService _passkeyMfaAuthenticationService;
        private readonly IAuthenticationFlowService _authenticationFlowService;

        public PasskeyController(
            IAppUserPasskeyManager passkeyManager,
            IEmailPasskeyAuthenticationService emailPasskeyAuthenticationService,
            IPasskeyMfaAuthenticationService passkeyMfaAuthenticationService,
            IAuthenticationFlowService authenticationFlowService,
            UserManager<AppUser> userManager,
            IAdminLogger logger) : base(userManager, logger)
        {
            _passkeyManager = passkeyManager ?? throw new ArgumentNullException(nameof(passkeyManager));
            _emailPasskeyAuthenticationService = emailPasskeyAuthenticationService ?? throw new ArgumentNullException(nameof(emailPasskeyAuthenticationService));
            _passkeyMfaAuthenticationService = passkeyMfaAuthenticationService ?? throw new ArgumentNullException(nameof(passkeyMfaAuthenticationService));
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
         * Email-bound authentication
         * ============================ */

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/email/authentication/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginEmailAuthenticationAsync([FromBody] PasskeyEmailAuthenticationBeginRequest request)
        {
            if (request == null)
                return Task.FromResult(InvokeResult<PasskeyBeginOptionsResponse>.FromError("passkey_request_required"));

            return _emailPasskeyAuthenticationService.BeginAsync(request.Email, request.PasskeyUrl, OrgEntityHeader, UserEntityHeader);
        }

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/email/authentication/complete")]
        public async Task<InvokeResult<AuthenticationResponse>> CompleteEmailAuthenticationAsync([FromBody] PasskeyEmailAuthenticationCompleteRequest request)
        {
            if (request?.Passkey == null)
                return InvokeResult<AuthenticationResponse>.FromError("passkey_request_required");

            var proof = await _emailPasskeyAuthenticationService.CompleteAsync(request.Email, request.Passkey, request.StepUp, OrgEntityHeader, UserEntityHeader);
            if (!proof.Successful || proof.Result == null)
                return InvokeResult<AuthenticationResponse>.FromInvokeResult(proof.ToInvokeResult());

            return await _authenticationFlowService.CompleteProvenUserSessionAsync(proof.Result, true);
        }

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/email/authentication/token")]
        public async Task<InvokeResult<AuthResponse>> CompleteEmailAuthenticationTokenAsync([FromBody] PasskeyEmailAuthenticationTokenCompleteRequest request)
        {
            if (request?.Passkey == null || request.Auth == null)
                return InvokeResult<AuthResponse>.FromError("passkey_and_auth_request_required");

            var proof = await _emailPasskeyAuthenticationService.CompleteAsync(request.Email, request.Passkey, request.StepUp, OrgEntityHeader, UserEntityHeader);
            if (!proof.Successful || proof.Result == null)
                return InvokeResult<AuthResponse>.FromInvokeResult(proof.ToInvokeResult());

            return await _authenticationFlowService.CompleteProvenUserTokenAsync(request.Auth, proof.Result);
        }

        /* ============================
         * Password-bound MFA authentication
         * ============================ */

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/mfa/authentication/begin")]
        public Task<InvokeResult<PasskeyBeginOptionsResponse>> BeginMfaAuthenticationAsync([FromBody] PasskeyMfaAuthenticationBeginRequest request)
        {
            if (request == null || String.IsNullOrWhiteSpace(request.MfaChallengeId))
                return Task.FromResult(InvokeResult<PasskeyBeginOptionsResponse>.FromError("mfa_challenge_required"));

            return _passkeyMfaAuthenticationService.BeginAsync(request.MfaChallengeId, request.PasskeyUrl, OrgEntityHeader, UserEntityHeader);
        }

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/mfa/authentication/complete")]
        public async Task<InvokeResult<AuthenticationResponse>> CompleteMfaAuthenticationAsync([FromBody] PasskeyMfaAuthenticationCompleteRequest request)
        {
            if (request?.Passkey == null || String.IsNullOrWhiteSpace(request.MfaChallengeId))
                return InvokeResult<AuthenticationResponse>.FromError("passkey_and_mfa_challenge_required");

            var proof = await _passkeyMfaAuthenticationService.CompleteAsync(request.MfaChallengeId, request.Passkey, OrgEntityHeader, UserEntityHeader);
            if (!proof.Successful || proof.Result == null)
                return InvokeResult<AuthenticationResponse>.FromInvokeResult(proof.ToInvokeResult());

            return await _authenticationFlowService.CompleteProvenUserSessionAsync(proof.Result, true);
        }

        [AllowAnonymous]
        [HttpPost("/api/auth/passkey/mfa/authentication/token")]
        public async Task<InvokeResult<AuthResponse>> CompleteMfaAuthenticationTokenAsync([FromBody] PasskeyMfaAuthenticationTokenCompleteRequest request)
        {
            if (request?.Passkey == null || request.Auth == null || String.IsNullOrWhiteSpace(request.MfaChallengeId))
                return InvokeResult<AuthResponse>.FromError("passkey_auth_and_mfa_challenge_required");

            var proof = await _passkeyMfaAuthenticationService.CompleteAsync(request.MfaChallengeId, request.Passkey, OrgEntityHeader, UserEntityHeader);
            if (!proof.Successful || proof.Result == null)
                return InvokeResult<AuthResponse>.FromInvokeResult(proof.ToInvokeResult());

            return await _authenticationFlowService.CompleteProvenUserTokenAsync(request.Auth, proof.Result);
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
        public Task<InvokeResult<PasskeySignInResult>> CompletePasswordlessAuthenticationAsync([FromBody] PasskeyAuthenticationCompleteRequest request)
        {
            return _passkeyManager.CompletePasswordlessAuthenticationAsync(request, OrgEntityHeader, UserEntityHeader);
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
