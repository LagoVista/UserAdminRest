using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Testing;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    /// <summary>
    /// App User Testing endpoints.
    /// Security will be applied externally (custom) - this controller is a thin pass-through to IAppUserTestingManager.
    /// </summary>
    [ConfirmedUser]
    public class AppUserTestingController : LagoVistaBaseController
    {
        private readonly IAppUserTestingManager _appUserTestingManager;

        public AppUserTestingController(IAppUserTestingManager appUserTestingManager, UserManager<Models.Users.AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _appUserTestingManager = appUserTestingManager ?? throw new ArgumentNullException(nameof(appUserTestingManager));
        }

        #region Preconditions / Setup

        [HttpDelete("/api/sys/testing/user")]
        public Task<InvokeResult> DeleteTestUserAsync() => _appUserTestingManager.DeleteTestUserAsync(OrgEntityHeader, UserEntityHeader);

        [HttpPost("/api/sys/testing/setup")]
        public Task<InvokeResult> ApplySetupAsync([FromBody] AuthTenantStateSnapshot request) => _appUserTestingManager.ApplySetupAsync(request, OrgEntityHeader, UserEntityHeader);

        [HttpGet("/api/sys/testing/token/email/last")]
        public Task<InvokeResult<string>> GetLastEmailTokenAsync() => _appUserTestingManager.GetLastEmailTokenAsync(OrgEntityHeader, UserEntityHeader);

        [HttpGet("/api/sys/testing/token/sms/last")]
        public Task<InvokeResult<string>> GetLastSmsTokenAsync() => _appUserTestingManager.GetLastSmsTokenAsync(OrgEntityHeader, UserEntityHeader);

        #endregion


        #region Auth View Management

        [HttpPost("/api/sys/testing/auth/view")]
        public Task<InvokeResult> CreateAuthViewAsync([FromBody] AuthView view) => _appUserTestingManager.AddAuthViewAsync(view, OrgEntityHeader, UserEntityHeader);

        [HttpPut("/api/sys/testing/auth/view")]
        public async Task<InvokeResult> UpdateAuthViewAsync([FromBody] AuthView scenario)
        {
            SetUpdatedProperties(scenario);
            return await _appUserTestingManager.UpdateAuthViewAsync(scenario, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sys/testing/auth/view/{id}")]
        public async Task<DetailResponse<AuthView>> GetAuthViewAsync(string id)
        {
            var authView = await _appUserTestingManager.GetAuthViewAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<AuthView>.Create(authView);
        }

        [HttpGet("/api/sys/testing/auth/view/factory")]
        public DetailResponse<AuthView> CreateAuthView()
        {
            var response = DetailResponse<AuthView>.Create();
            SetOwnedProperties(response.Model);
            SetAuditProperties(response.Model);
            return response;
        }

        [HttpPost("/api/sys/testing/auth/views")]
        public Task<ListResponse<AuthViewSummary>> GetAuthViewsAsync() => _appUserTestingManager.GetAuthViewsForOrgAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);

        [HttpDelete("/api/sys/testing/auth/view/{id}")]
        public Task<InvokeResult> DeleteAuthViewAsync(string id) => _appUserTestingManager.DeleteAuthViewAsync(id, OrgEntityHeader, UserEntityHeader);

        #endregion

        #region Test Scenario Management

        [HttpPost("/api/sys/testing/auth/scenario")]
        public Task<InvokeResult> CreateTesteScanarioAsync([FromBody] AppUserTestScenario scenario) => _appUserTestingManager.AddTestScenarioAsync(scenario, OrgEntityHeader, UserEntityHeader);

        [HttpPut("/api/sys/testing/auth/scenario")]
        public async Task<InvokeResult> UpdateTestScenarioAsync([FromBody] AppUserTestScenario scenario)
        {
            SetUpdatedProperties(scenario);
            return await _appUserTestingManager.UpdateTestScenarioAsync(scenario, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sys/testing/auth/scenario/{id}")]
        public async Task<DetailResponse<AppUserTestScenario>> GetTestScenarioAsync(string id)
        {
            var scenario = await _appUserTestingManager.GetTestScenarioAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<AppUserTestScenario>.Create(scenario);
        }

        [HttpGet("/api/sys/testing/auth/scenario/factory")]
        public DetailResponse<AppUserTestScenario> CreateTestScenario()
        {
            var response = DetailResponse<AppUserTestScenario>.Create();
            SetOwnedProperties(response.Model);
            SetAuditProperties(response.Model);
            return response;
        }

        [HttpPost("/api/sys/testing/auth/scenarios")]
        public Task<ListResponse<AppUserTestScenarioSummary>> GetTestScenariosAsync() => _appUserTestingManager.GetTestScenariosForOrganizationAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);

        [HttpDelete("/api/sys/testing/auth/scenario/{id}")]
        public Task<InvokeResult> DeleteTestScanarioAsync(string id) => _appUserTestingManager.DeleteTestScenarioAsync(id, OrgEntityHeader, UserEntityHeader);

        #endregion

        #region Run Persistence

        [HttpPost("/api/sys/testing/auth/run")]
        public Task<InvokeResult> CreateRunAsync([FromBody] AppUserTestRun run) => _appUserTestingManager.AddTestRunAsync(run, OrgEntityHeader, UserEntityHeader);

        [HttpPost("/api/sys/testing/auth/run/{runId}/event")]
        public Task<InvokeResult> AppendRunEventAsync(string runId, [FromBody] AppUserTestRunEvent evt) => _appUserTestingManager.AppendRunEventAsync(runId, evt, OrgEntityHeader, UserEntityHeader);

        public class FinishRunRequest
        {
            public TestRunStatus Status { get; set; }
            public TestRunVerification Verification { get; set; }
        }

        [HttpPost("/api/sys/testing/auth/run/{runId}/finish")]
        public Task<InvokeResult> FinishRunAsync(string runId, [FromBody] FinishRunRequest request)
        {
            return _appUserTestingManager.FinishRunAsync(runId, request.Status, OrgEntityHeader, UserEntityHeader, request.Verification);
        }

        [HttpPost("/api/sys/testing/auth/runs")]
        public Task<ListResponse<AppUserTestRunSummary>> GetTestRunsAsync() => _appUserTestingManager.GetTestRunsAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);

        [HttpGet("/api/sys/testing/auth/run/{runId}")]
        public async Task<InvokeResult<AppUserTestRun>> GetRunAsync(string runId)
        {
            var result = await  _appUserTestingManager.GetTestRunAsync(runId, OrgEntityHeader, UserEntityHeader);
            return InvokeResult<AppUserTestRun>.Create(result);
        }

        #endregion

        #region Auth Log Review

        [HttpGet("/api/sys/testing/authlog/review")]
        public Task<InvokeResult<AuthLogReviewSummary>> GetAuthLogReviewAsync([FromQuery] DateTime fromUtc, [FromQuery] DateTime toUtc)
            => _appUserTestingManager.GetAuthLogReviewAsync(fromUtc, toUtc, OrgEntityHeader, UserEntityHeader);

        #endregion
    }
}
