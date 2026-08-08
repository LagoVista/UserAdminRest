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
    [ApiController]
    [Authorize]
    public class ProvisionalEnvironmentController : LagoVistaBaseController
    {
        private readonly IProvisionalEnvironmentManager _provisionalEnvironmentManager;

        public ProvisionalEnvironmentController(IProvisionalEnvironmentManager provisionalEnvironmentManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _provisionalEnvironmentManager = provisionalEnvironmentManager ?? throw new ArgumentNullException(nameof(provisionalEnvironmentManager));
        }

        [AllowAnonymous]
        [HttpPost("/api/provisional/environment")]
        public Task<InvokeResult<CreateProvisionalEnvironmentResponse>> CreateAsync([FromBody] CreateProvisionalEnvironmentRequest request)
        {
            return _provisionalEnvironmentManager.CreateAsync(request);
        }

        [AllowAnonymous]
        [HttpPost("/api/provisional/environment/restore")]
        public Task<InvokeResult<RestoreProvisionalEnvironmentResponse>> RestoreAsync([FromBody] RestoreProvisionalEnvironmentRequest request)
        {
            return _provisionalEnvironmentManager.RestoreAsync(request);
        }

        [HttpPost("/api/provisional/environment/{provisionalEnvironmentId}/claim")]
        public Task<InvokeResult> ClaimAsync(string provisionalEnvironmentId)
        {
            return _provisionalEnvironmentManager.ClaimAsync(provisionalEnvironmentId, UserEntityHeader.Id);
        }

        [SystemAdmin]
        [HttpGet("/api/sys/provisional/environments/{state}")]
        public Task<InvokeResult<IEnumerable<ProvisionalEnvironmentLifecycleSummary>>> GetByStateAsync(ProvisionalEnvironmentState state, [FromQuery] DateTime? dueBeforeUtc = null, [FromQuery] int take = 100)
        {
            return _provisionalEnvironmentManager.GetByStateAsync(state, dueBeforeUtc, take);
        }

        [SystemAdmin]
        [HttpPost("/api/sys/provisional/environments/expire")]
        public Task<InvokeResult<ProvisionalEnvironmentLifecycleBatchResult>> ExpireAsync([FromQuery] DateTime? asOfUtc = null, [FromQuery] int take = 100)
        {
            return _provisionalEnvironmentManager.ExpireAsync(asOfUtc, take);
        }

        [SystemAdmin]
        [HttpPost("/api/sys/provisional/environments/prepare-for-purge")]
        public Task<InvokeResult<ProvisionalEnvironmentLifecycleBatchResult>> PrepareForPurgeAsync([FromQuery] DateTime? asOfUtc = null, [FromQuery] int take = 100)
        {
            return _provisionalEnvironmentManager.PrepareForPurgeAsync(asOfUtc, take);
        }

        [SystemAdmin]
        [HttpPost("/api/sys/provisional/environments/purge")]
        public Task<InvokeResult<ProvisionalEnvironmentLifecycleBatchResult>> PurgeAsync([FromQuery] int take = 100)
        {
            return _provisionalEnvironmentManager.PurgeAsync(take);
        }
    }
}
