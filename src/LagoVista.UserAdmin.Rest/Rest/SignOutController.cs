using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Authentication;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class SignOutController : LagoVistaBaseController
    {
        private readonly IAuthenticationFlowService _authenticationFlowService;

        public SignOutController(IAuthenticationFlowService authenticationFlowService, UserManager<AppUser> userManager, IAdminLogger logger)
            : base(userManager, logger)
        {
            _authenticationFlowService = authenticationFlowService ?? throw new ArgumentNullException(nameof(authenticationFlowService));
        }

        [HttpPost("/api/auth/signout")]
        public Task<InvokeResult> SignOutAsync([FromBody] SignOutRequest request)
        {
            return _authenticationFlowService.SignOutAsync(request, OrgEntityHeader, UserEntityHeader);
        }
    }
}
