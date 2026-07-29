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
    }
}
