using LagoVista.Core.Authentication.Models;
using LagoVista.Core.Validation;
using LagoVista.UserAdmin.Authentication;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [ApiController]
    [AllowAnonymous]
    public class AuthenticationFlowController : ControllerBase
    {
        private readonly IAuthenticationFlowService _authenticationFlowService;
        private readonly IPendingIdentityManager _pendingIdentityManager;
        private readonly IPendingIdentityResolutionService _pendingIdentityResolutionService;

        public AuthenticationFlowController(
            IAuthenticationFlowService authenticationFlowService,
            IPendingIdentityManager pendingIdentityManager,
            IPendingIdentityResolutionService pendingIdentityResolutionService)
        {
            _authenticationFlowService = authenticationFlowService ?? throw new ArgumentNullException(nameof(authenticationFlowService));
            _pendingIdentityManager = pendingIdentityManager ?? throw new ArgumentNullException(nameof(pendingIdentityManager));
            _pendingIdentityResolutionService = pendingIdentityResolutionService ?? throw new ArgumentNullException(nameof(pendingIdentityResolutionService));
        }

        [HttpPost("/api/auth/password/login")]
        public Task<InvokeResult<AuthenticationResponse>> LoginWithPasswordAsync([FromBody] AuthLoginRequest request)
        {
            request.InviteId = Request.Cookies["inviteid"];
            Response.Cookies.Delete("inviteid");

            return _authenticationFlowService.LoginWithPasswordAsync(request);
        }

        [HttpPost("/api/auth/password/mfa-challenge")]
        public Task<InvokeResult<AuthenticationResponse>> CreatePasswordMfaChallengeAsync([FromBody] AuthLoginRequest request)
        {
            return _authenticationFlowService.CreatePasswordMfaChallengeAsync(request);
        }

        [HttpPost("/api/auth/totp/login")]
        public Task<InvokeResult<AuthenticationResponse>> AuthenticateWithTotpAsync([FromBody] TotpSignInRequest request)
        {
            return _authenticationFlowService.AuthenticateWithTotpAsync(request);
        }

        [HttpPost("/api/auth/totp/token")]
        public Task<InvokeResult<AuthResponse>> AuthenticateWithTotpTokenAsync([FromBody] TotpTokenSignInRequest request)
        {
            return _authenticationFlowService.AuthenticateWithTotpTokenAsync(request);
        }

        [HttpPost("/api/auth/mfarecovery/login")]
        public Task<InvokeResult<AuthenticationResponse>> AuthenticateWithRecoveryCodeAsync([FromBody] RecoveryCodeSignInRequest request)
        {
            return _authenticationFlowService.AuthenticateWithRecoveryCodeAsync(request);
        }

        [HttpPost("/api/auth/mfarecovery/token")]
        public Task<InvokeResult<AuthResponse>> AuthenticateWithRecoveryCodeTokenAsync([FromBody] RecoveryCodeTokenSignInRequest request)
        {
            return _authenticationFlowService.AuthenticateWithRecoveryCodeTokenAsync(request);
        }

        /// <summary>
        /// Updates the untrusted registration/profile information collected during a PendingIdentity ceremony.
        /// The supplied email remains untrusted until the independent NuvIoT verification step succeeds.
        /// </summary>
        [HttpPost("/api/auth/pending-identity/{pendingIdentityId}/registration")]
        public async Task<InvokeResult> UpdatePendingIdentityRegistrationAsync(string pendingIdentityId, [FromBody] RegisterUser request)
        {
            if (String.IsNullOrWhiteSpace(pendingIdentityId))
                return InvokeResult.FromError("Pending identity id is required.");

            if (request == null)
                return InvokeResult.FromError("Registration details are required.");

            await _pendingIdentityManager.AddRegistrationAsync(pendingIdentityId, request);
            return InvokeResult.Success;
        }

        /// <summary>
        /// Sends or resends the independent NuvIoT email-verification proof for a PendingIdentity ceremony.
        /// A PendingIdentity id is a ceremony handle only; this operation does not establish application authorization.
        /// </summary>
        [HttpPost("/api/auth/pending-identity/{pendingIdentityId}/email/send")]
        public Task<InvokeResult<string>> SendPendingIdentityEmailVerificationAsync(string pendingIdentityId)
        {
            if (String.IsNullOrWhiteSpace(pendingIdentityId))
                return Task.FromResult(InvokeResult<string>.FromError("Pending identity id is required."));

            return _pendingIdentityManager.SendEmailVerificationAsync(pendingIdentityId);
        }

        /// <summary>
        /// Verifies the NuvIoT email code for a PendingIdentity and moves the ceremony to identity resolution.
        /// This does not create, link, or authenticate a durable user by itself.
        /// </summary>
        [HttpPost("/api/auth/pending-identity/{pendingIdentityId}/email/verify")]
        public Task<InvokeResult> VerifyPendingIdentityEmailAsync(string pendingIdentityId, [FromBody] ConfirmEmail request)
        {
            if (String.IsNullOrWhiteSpace(pendingIdentityId))
                return Task.FromResult(InvokeResult.FromError("Pending identity id is required."));

            return _pendingIdentityManager.VerifyEmailAsync(pendingIdentityId, request?.ReceivedCode);
        }

        /// <summary>
        /// Resolves an independently email-verified OAuth PendingIdentity to a durable user.
        /// Existing verified-email matches are linked; otherwise a new durable user is created.
        /// This operation does not apply invitation context or establish a normal application session.
        /// </summary>
        [HttpPost("/api/auth/pending-identity/{pendingIdentityId}/resolve/oauth")]
        public Task<InvokeResult<AppUser>> ResolvePendingIdentityOAuthAsync(string pendingIdentityId, [FromBody] RegisterUser request)
        {
            if (String.IsNullOrWhiteSpace(pendingIdentityId))
                return Task.FromResult(InvokeResult<AppUser>.FromError("Pending identity id is required."));

            return _pendingIdentityResolutionService.ResolveOAuthAsync(pendingIdentityId, request);
        }
    }
}
