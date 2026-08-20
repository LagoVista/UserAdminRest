using LagoVista.Core.Authentication.Models;
using LagoVista.Core.Validation;
using LagoVista.UserAdmin.Authentication;
using LagoVista.UserAdmin.Models.Auth;
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

        public AuthenticationFlowController(IAuthenticationFlowService authenticationFlowService)
        {
            _authenticationFlowService = authenticationFlowService ?? throw new ArgumentNullException(nameof(authenticationFlowService));
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
    }
}
