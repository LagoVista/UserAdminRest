// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: ceb8d52133ef0c2b8c6e288aac7dec9c17de8fb12adead00d4014bf103c13134
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Models;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Orgs;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System;
using LagoVista.UserAdmin.Models.Security;
using LagoVista.Core;

namespace LagoVista.UserAdmin.Rest
{

    [Authorize]
    public class FunctionMapController : LagoVistaBaseController
    {
        private readonly IFunctionMapManager _manager;

        public FunctionMapController(IFunctionMapManager manager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        }

        [HttpPost("/api/function/map")]
        public Task<InvokeResult> AddFunctionMapAsync([FromBody] FunctionMap functionMap)
        {
            return _manager.AddFunctionMapAsync(functionMap, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPut("/api/function/map")]
        public Task<InvokeResult> UpdateFunctionMapAsync([FromBody] FunctionMap functionMap)
        {
            SetUpdatedProperties(functionMap);
            return _manager.UpdateFunctionMapAsync(functionMap, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/function/map/root")]
        public async Task<DetailResponse<FunctionMap>> GetTopLevelMap()
        {
            var functionMap = await _manager.GetTopLevelFunctionMapAsync(OrgEntityHeader, UserEntityHeader);
            if (functionMap == null)
            {
                var top = CreateFunctionMap();
                top.Model.TopLevel = true;
                return top;
            }
            else
                return DetailResponse<FunctionMap>.Create(functionMap);
        }

        [HttpGet("/api/function/map/{id}")]
        public async Task<DetailResponse<FunctionMap>> GetFunctionMapAsync(String id)
        {
            var functionMap = await _manager.GetFunctionMapAsync(id, OrgEntityHeader, UserEntityHeader);

            return DetailResponse<FunctionMap>.Create(functionMap);
        }


        [HttpGet("/api/function/map/key/{key}")]
        public async Task<DetailResponse<FunctionMap>> GetFunctionMapByKey(String key)
        {
            var functionMap = await _manager.GetFunctionMapByKeyAsync(key, OrgEntityHeader, UserEntityHeader);

            return DetailResponse<FunctionMap>.Create(functionMap);
        }

        [HttpDelete("/api/function/map/{id}")]
        public Task<InvokeResult> DeleteFunctionMapAsync(string id)
        {
            return _manager.DeleteFunctionMapAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/function/map/factory")]
        public DetailResponse<FunctionMap> CreateFunctionMap()
        {
            var response = DetailResponse<FunctionMap>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }

       [HttpGet("/api/function/map/function/factory")]
        public DetailResponse<FunctionMapFunction> CreateFunctionMapFunction()
        {
            return DetailResponse<FunctionMapFunction>.Create();
        }

    }
}
