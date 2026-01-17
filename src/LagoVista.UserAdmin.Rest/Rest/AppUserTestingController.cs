using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
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
    public class AppUserTestingController : LagoVistaBaseController
    {
        private readonly IAppUserTestingManager _appUserTestingManager;

        public AppUserTestingController(IAppUserTestingManager appUserTestingManager, UserManager<Models.Users.AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _appUserTestingManager = appUserTestingManager ?? throw new ArgumentNullException(nameof(appUserTestingManager));
        }

        #region Preconditions / Setup

        [HttpPost("/api/appuser/testing/signin")]
        public Task<InvokeResult> SignInTestUser() => _appUserTestingManager.SignInTestUser();

        [HttpPost("/api/appuser/testing/signout")]
        public Task<InvokeResult> SignOutTestUser() => _appUserTestingManager.SignOutTestUser();

        [HttpDelete("/api/appuser/testing/user")]
        public Task<InvokeResult> DeleteTestUserAsync() => _appUserTestingManager.DeleteTestUserAsync();

        public class ApplySetupRequest
        {
            public AuthTenantStateSnapshot Preconditions { get; set; }
            public bool LoginUser { get; set; }
        }

        [HttpPost("/api/appuser/testing/setup")]
        public Task<InvokeResult> ApplySetupAsync([FromBody] ApplySetupRequest request) => _appUserTestingManager.ApplySetupAsync(request.Preconditions, request.LoginUser);

        [HttpGet("/api/appuser/testing/token/email/last")]
        public Task<InvokeResult<string>> GetLastEmailTokenAsync() => _appUserTestingManager.GetLastEmailTokenAsync();

        [HttpGet("/api/appuser/testing/token/sms/last")]
        public Task<InvokeResult<string>> GetLastSmsTokenAsync() => _appUserTestingManager.GetLastSmsTokenAsync();

        #endregion

        #region Snapshot Getter

        [HttpGet("/api/appuser/testing/snapshot")]
        public Task<InvokeResult<AuthTenantStateSnapshot>> GetUserSnapshotAsync([FromQuery] string ceremonyId = null) => _appUserTestingManager.GetUserSnapshotAsync(ceremonyId);

        [HttpGet("/api/appuser/testing/verification")]
        public Task<InvokeResult<TestRunVerification>> GetVerificationAsync([FromQuery] string ceremonyId = null) => _appUserTestingManager.GetVerificationAsync(ceremonyId);

        #endregion

        #region DSL Case Management

        [HttpPost("/api/appuser/testing/dsl")]
        public Task<InvokeResult> CreateDslAsync([FromBody] AppUserTestingDSL dsl) => _appUserTestingManager.CreateDslAsync(dsl);

        [HttpPut("/api/appuser/testing/dsl")]
        public Task<InvokeResult> UpdateDslAsync([FromBody] AppUserTestingDSL dsl) => _appUserTestingManager.UpdateDslAsync(dsl);

        [HttpGet("/api/appuser/testing/dsl/{id}")]
        public Task<InvokeResult<AppUserTestingDSL>> GetDslAsync(string id) => _appUserTestingManager.GetDslAsync(id);

        [HttpPost("/api/appuser/testing/dsls")]
        public Task<ListResponse<AppUserTestingDSLSummary>> ListDslAsync() => _appUserTestingManager.ListDslAsync(GetListRequestFromHeader());

        [HttpDelete("/api/appuser/testing/dsl/{id}")]
        public Task<InvokeResult> DeleteDslAsync(string id) => _appUserTestingManager.DeleteDslAsync(id);

        #endregion

        #region Run Persistence

        [HttpPost("/api/appuser/testing/run")]
        public Task<InvokeResult<AppUserTestRun>> CreateRunAsync([FromBody] AppUserTestRun run) => _appUserTestingManager.CreateRunAsync(run);

        [HttpPost("/api/appuser/testing/run/{runId}/event")]
        public Task<InvokeResult> AppendRunEventAsync(string runId, [FromBody] AppUserTestRunEvent evt) => _appUserTestingManager.AppendRunEventAsync(runId, evt);

        public class FinishRunRequest
        {
            public TestRunStatus Status { get; set; }
            public TestRunVerification Verification { get; set; }
        }

        [HttpPost("/api/appuser/testing/run/{runId}/finish")]
        public Task<InvokeResult<AppUserTestRun>> FinishRunAsync(string runId, [FromBody] FinishRunRequest request)
        {
            if (request == null)
            {
                return Task.FromResult(InvokeResult<AppUserTestRun>.FromError("Missing request body."));
            }

            return _appUserTestingManager.FinishRunAsync(runId, request.Status, request.Verification);
        }

        [HttpPost("/api/appuser/testing/runs")]
        public Task<ListResponse<AppUserTestRunSummary>> GetTestRunsAsync()
            => _appUserTestingManager.GetTestRunsAsync(GetListRequestFromHeader());

        [HttpGet("/api/appuser/testing/run/{runId}")]
        public Task<InvokeResult<AppUserTestRun>> GetRunAsync(string runId) => _appUserTestingManager.GetRunAsync(runId);

        #endregion

        #region Auth Log Review

        [HttpGet("/api/appuser/testing/authlog/review")]
        public Task<InvokeResult<AuthLogReviewSummary>> GetAuthLogReviewAsync([FromQuery] DateTime fromUtc, [FromQuery] DateTime toUtc)
            => _appUserTestingManager.GetAuthLogReviewAsync(fromUtc, toUtc);

        #endregion
    }
}
