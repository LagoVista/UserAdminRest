using LagoVista.Core.Models.UIMetaData;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Testing;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    public class AppUserTestingDashboardController : ControllerBase
    {
        private readonly IAppUserTestingManager _appUserTestingManager;

        public AppUserTestingDashboardController(IAppUserTestingManager appUserTestingManager)
        {
            _appUserTestingManager = appUserTestingManager ?? throw new ArgumentNullException(nameof(appUserTestingManager));
        }

        [AllowAnonymous]
        [HttpGet("/api/sys/testing/auth/dashboard")]
        public Task<ListResponse<AppUserTestScenarioSummary>> GetDashboardAsync() => _appUserTestingManager.GetPublicTestScenarioDashboardAsync(ListRequest.CreateForAll());
    }
}
