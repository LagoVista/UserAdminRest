using LagoVista.Core;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Orgs;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    /// <summary>
    /// Optional organization-owned business units. All operations are scoped to the current organization.
    /// </summary>
    [Authorize]
    [ConfirmedUser]
    public class BusinessUnitController : LagoVistaBaseController
    {
        private readonly IBusinessUnitManager _manager;

        public BusinessUnitController(IBusinessUnitManager manager, UserManager<AppUser> userManager,
            IAdminLogger logger) : base(userManager, logger)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        }

        [McpEndpoint("business-unit-create", Description = "Create a business unit within the current organization.", FamilyId = "orgs")]
        [HttpPost("/api/org/businessunit")]
        public Task<InvokeResult> AddBusinessUnitAsync([FromBody] BusinessUnit businessUnit)
        {
            SetAuditProperties(businessUnit);
            SetOwnedProperties(businessUnit);
            return _manager.AddBusinessUnitAsync(businessUnit, OrgEntityHeader, UserEntityHeader);
        }

        [McpEndpoint("business-unit-update", Description = "Update an existing business unit in the current organization.", FamilyId = "orgs")]
        [HttpPut("/api/org/businessunit")]
        public Task<InvokeResult> UpdateBusinessUnitAsync([FromBody] BusinessUnit businessUnit)
        {
            SetUpdatedProperties(businessUnit);
            return _manager.UpdateBusinessUnitAsync(businessUnit, OrgEntityHeader, UserEntityHeader);
        }

        [McpEndpoint("business-unit-list", Description = "List business units belonging to the current organization.", FamilyId = "orgs")]
        [HttpGet("/api/org/businessunits")]
        public Task<ListResponse<BusinessUnitSummary>> GetBusinessUnitsAsync()
        {
            return _manager.GetBusinessUnitsForOrgAsync(OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        [McpEndpoint("business-unit-get", Description = "Get a business unit in the current organization by ID.", FamilyId = "orgs")]
        [HttpGet("/api/org/businessunit/{id}")]
        public async Task<DetailResponse<BusinessUnit>> GetBusinessUnitAsync(string id)
        {
            var businessUnit = await _manager.GetBusinessUnitAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<BusinessUnit>.Create(businessUnit);
        }

        [McpEndpoint("business-unit-key-in-use", Description = "Check whether a business unit key is already used in the current organization.", FamilyId = "orgs")]
        [HttpGet("/api/org/businessunit/{key}/keyinuse")]
        public Task<bool> GetBusinessUnitKeyInUseAsync(string key)
        {
            return _manager.QueryKeyInUseAsync(key, OrgEntityHeader, UserEntityHeader);
        }

        [McpEndpoint("business-unit-in-use", Description = "Check whether a business unit has registered dependencies before deletion.", FamilyId = "orgs")]
        [HttpGet("/api/org/businessunit/{id}/inuse")]
        public Task<DependentObjectCheckResult> CheckBusinessUnitInUseAsync(string id)
        {
            return _manager.CheckBusinessUnitInUseAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [McpEndpoint("business-unit-delete", Description = "Delete a business unit in the current organization when it has no registered dependencies.", FamilyId = "orgs")]
        [HttpDelete("/api/org/businessunit/{id}")]
        public Task<InvokeResult> DeleteBusinessUnitAsync(string id)
        {
            return _manager.DeleteBusinessUnitAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [McpEndpoint("business-unit-factory", Description = "Get an unsaved business unit template owned by the current organization.", FamilyId = "orgs")]
        [HttpGet("/api/org/businessunit/factory")]
        public DetailResponse<BusinessUnit> CreateBusinessUnit()
        {
            var response = DetailResponse<BusinessUnit>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }
    }
}
