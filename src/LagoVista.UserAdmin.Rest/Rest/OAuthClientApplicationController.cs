using LagoVista.Core;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
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
    public class OAuthClientApplicationController : LagoVistaBaseController
    {
        private readonly IOAuthClientApplicationManager _manager;

        public OAuthClientApplicationController(IOAuthClientApplicationManager manager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        }

        [HttpPost("/api/oauth/client")]
        public Task<InvokeResult> AddOAuthClientApplicationAsync([FromBody] OAuthClientApplication client)
        {
            return _manager.AddOAuthClientApplicationAsync(client, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPut("/api/oauth/client")]
        public Task<InvokeResult> UpdateOAuthClientApplicationAsync([FromBody] OAuthClientApplication client)
        {
            SetUpdatedProperties(client);
            return _manager.UpdateOAuthClientApplicationAsync(client, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/oauth/clients")]
        public Task<ListResponse<OAuthClientApplicationSummary>> GetOAuthClientApplicationsForOrgAsync()
        {
            return _manager.GetOAuthClientApplicationsForOrgAsync(OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        [HttpGet("/api/oauth/client/{id}/inuse")]
        public Task<DependentObjectCheckResult> CheckOAuthClientApplicationInUseAsync(string id)
        {
            return _manager.CheckOAuthClientApplicationInUseAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/oauth/client/{id}")]
        public async Task<DetailResponse<OAuthClientApplication>> GetOAuthClientApplicationAsync(string id)
        {
            var client = await _manager.GetOAuthClientApplicationAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<OAuthClientApplication>.Create(client);
        }

        [HttpGet("/api/oauth/client/{key}/keyinuse")]
        public Task<bool> GetOAuthClientApplicationKeyInUseAsync(string key)
        {
            return _manager.QueryKeyInUseAsync(key, OrgEntityHeader);
        }

        [HttpGet("/api/oauth/client/clientid/{clientId}/inuse")]
        public Task<bool> GetOAuthClientIdInUseAsync(string clientId, [FromQuery] string currentId = null)
        {
            return _manager.QueryClientIdInUseAsync(clientId, currentId);
        }

        [HttpDelete("/api/oauth/client/{id}")]
        public Task<InvokeResult> DeleteOAuthClientApplicationAsync(string id)
        {
            return _manager.DeleteOAuthClientApplicationAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/oauth/client/factory")]
        public DetailResponse<OAuthClientApplication> CreateOAuthClientApplication()
        {
            var response = DetailResponse<OAuthClientApplication>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }

        [HttpGet("/api/oauth/client/value/factory")]
        public DetailResponse<OAuthClientSettingValue> CreateOAuthClientSettingValue()
        {
            return DetailResponse<OAuthClientSettingValue>.Create();
        }
    }
}
