using LagoVista.Core;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Billing.Models;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Security;
using LagoVista.UserAdmin.Models.Testing;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        [HttpGet("/api/sys/testing/token/email/last")]
        public Task<InvokeResult<string>> GetLastEmailTokenAsync() => _appUserTestingManager.GetLastEmailTokenAsync(OrgEntityHeader, UserEntityHeader);

        [HttpGet("/api/sys/testing/token/sms/last")]
        public Task<InvokeResult<string>> GetLastSmsTokenAsync() => _appUserTestingManager.GetLastSmsTokenAsync(OrgEntityHeader, UserEntityHeader);

        #endregion


        #region Auth View Management

        [HttpPost("/api/sys/testing/authview")]
        public Task<InvokeResult> CreateAuthViewAsync([FromBody] AuthView view) => _appUserTestingManager.AddAuthViewAsync(view, OrgEntityHeader, UserEntityHeader);

        [HttpPut("/api/sys/testing/authview")]
        public async Task<InvokeResult> UpdateAuthViewAsync([FromBody] AuthView scenario)
        {
            SetUpdatedProperties(scenario);
            return await _appUserTestingManager.UpdateAuthViewAsync(scenario, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sys/testing/authview/{id}")]
        public async Task<DetailResponse<AuthView>> GetAuthViewAsync(string id)
        {
            var authView = await _appUserTestingManager.GetAuthViewAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<AuthView>.Create(authView);
        }

        [HttpGet("/api/sys/testing/authview/factory")]
        public DetailResponse<AuthView> CreateAuthView()
        {
            var response = DetailResponse<AuthView>.Create();
            SetOwnedProperties(response.Model);
            SetAuditProperties(response.Model);
            return response;
        }

        [HttpGet("/api/sys/testing/authview/field/factory")]
        public DetailResponse<AuthViewField> CreateAuthViewField()
        {
            var response = DetailResponse<AuthViewField>.Create();
            return response;
        }

        [HttpGet("/api/sys/testing/auth/usersnapshot/factory")]
        public DetailResponse<AuthTenantStateSnapshot> CreateAuthTenantStateSnapshot()
        {
            var response = DetailResponse<AuthTenantStateSnapshot>.Create();
            return response;
        }


        [HttpGet("/api/sys/testing/authview/action/factory")]
        public DetailResponse<AuthFieldAction> CreateAction()
        {
            var response = DetailResponse<AuthFieldAction>.Create();
            return response;
        }

        [HttpGet("/api/sys/testing/authviews")]
        public Task<ListResponse<AuthViewSummary>> GetAuthViewsAsync() => _appUserTestingManager.GetAuthViewsForOrgAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);

        [HttpDelete("/api/sys/testing/authview/{id}")]
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
            var view = DetailResponse<AppUserTestScenario>.Create(scenario);
            var views = await _appUserTestingManager.GetAuthViewsForOrgAsync(ListRequest.CreateForAll(), OrgEntityHeader, UserEntityHeader);
            var options = views.Model.Select(view => view.CreateEnumDescription()).ToList();
            options.Insert(0, EnumDescription.CreateSelect());
            view.View[nameof(AppUserTestScenario.AuthView).CamelCase()].Options = options;
            view.View[nameof(AppUserTestScenario.ExpectedView).CamelCase()].Options = options;
            return view;
        }

        [HttpGet("/api/sys/testing/auth/scenario/{id}/plan")]
        public async Task<InvokeResult<AuthRunnerPlan>> GetTestScenarioPlanAsync(string id, bool headless)
        {
            return await _appUserTestingManager.BuildRunnerPlanAsync(id, headless, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sys/testing/auth/scenario/factory")]
        public async Task<DetailResponse<AppUserTestScenario>> CreateTestScenario()
        {
            var response = DetailResponse<AppUserTestScenario>.Create();
            SetOwnedProperties(response.Model);
            SetAuditProperties(response.Model);

            var views = await _appUserTestingManager.GetAuthViewsForOrgAsync(ListRequest.CreateForAll(), OrgEntityHeader, UserEntityHeader);
            var options = views.Model.Select(view => view.CreateEnumDescription()).ToList();
            options.Insert(0, EnumDescription.CreateSelect());
            response.View[nameof(AppUserTestScenario.AuthView).CamelCase()].Options = options;
            response.View[nameof(AppUserTestScenario.ExpectedView).CamelCase()].Options = options;
            return response;
        }

        public static async Task<byte[]> ReadBytesAsync(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Array.Empty<byte>();

            await using var ms = new MemoryStream((int)file.Length);
            await file.CopyToAsync(ms);
            return ms.ToArray();
        }

        [HttpPost("/api/sys/testing/auth/run/complete")]
        public async Task<InvokeResult> CompleteRunAsync([FromForm] string resultJson, List<IFormFile> files)
        {
            Console.WriteLine("[api] - arrived.");
            Console.WriteLine($"[api] - fileCount {files.Count}.");


            Console.WriteLine($"[JSON.TESTRUN]={resultJson}");

            var runnerResult = JsonConvert.DeserializeObject<AppUserTestRun>(resultJson);

            var testArtifacts = new List<ArtifactFlie>();

            foreach (var file in files)
            {
                testArtifacts.Add(new ArtifactFlie()
                {
                    FileName = file.FileName,
                    Buffer = await ReadBytesAsync(file),
                    ContentType = file.ContentType
                }); 
            }
         
            await _appUserTestingManager.AddTestRunAsync(runnerResult, testArtifacts, OrgEntityHeader, UserEntityHeader);

            return InvokeResult.Success;
        }

        [HttpGet("/api/sys/testing/auth/scenarios")]
        public Task<ListResponse<AppUserTestScenarioSummary>> GetTestScenariosAsync() => _appUserTestingManager.GetTestScenariosForOrganizationAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);

        [HttpDelete("/api/sys/testing/auth/scenario/{id}")]
        public Task<InvokeResult> DeleteTestScanarioAsync(string id) => _appUserTestingManager.DeleteTestScenarioAsync(id, OrgEntityHeader, UserEntityHeader);

        #endregion

        #region Run Persistence

        public class FinishRunRequest
        {
            public TestRunStatus Status { get; set; }
            public TestRunVerification Verification { get; set; }
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
        public Task<ListResponse<AuthenticationLog>> GetAuthLogReviewAsync() => _appUserTestingManager.GetAuthLogReviewAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);

        #endregion
    }
}
