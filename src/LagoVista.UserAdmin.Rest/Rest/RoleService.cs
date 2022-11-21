using LagoVista.Core;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Security;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class RoleService : LagoVistaBaseController
    {
        private readonly IRoleManager _roleManager;

        public RoleService(IRoleManager userRoleManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _roleManager = userRoleManager ?? throw new ArgumentNullException(nameof(userRoleManager));
        }

        [HttpGet("/api/sys/roles")]
        public Task<List<RoleSummary>> GetRolesAsync()
        {
            return _roleManager.GetRolesAsync(OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sys/roles/assignable")]
        public Task<List<RoleSummary>> GetAssignableRolesAsync()
        {
            return _roleManager.GetAssignableRolesAsync(OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sys/role/{id}")]
        public async Task<DetailResponse<Role>> GetRolesAsync(string id)
        {
            var role = await _roleManager.GetRoleAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<Role>.Create(role);
        }

        [HttpGet("/api/sys/role/factory")]
        public async Task<DetailResponse<Role>> GetNewRole()
        {
            var response = DetailResponse<Role>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }

        [HttpGet("/api/sys/role/{roleid}/access")]
        public Task<List<RoleAccess>> GetRoleAcess(string roleid)
        {
            return _roleManager.GetRoleAccessAsync(roleid, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/api/sys/role/access")]
        public Task<InvokeResult> AddRoleAcessAsync([FromBody] RoleAccess access)
        {
            return _roleManager.AddRoleAccessAsync(access, OrgEntityHeader, UserEntityHeader);
        }

        [HttpDelete("/api/sys/role/access/{id}")]
        public Task<InvokeResult> UpdateRoleAcessAsync(string id)
        {
            return _roleManager.RevokeRoleAccessAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/api/sys/role")]
        public Task<InvokeResult> PostRolesAsync([FromBody] Role role)
        {
            return _roleManager.AddRoleAsync(role, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPut("/api/sys/role")]
        public Task<InvokeResult> PutRolesAsync([FromBody] Role role)
        {
            return _roleManager.UpdateRoleAsync(role, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sys/role/{roleid}/access/factory")]
        public async Task<RoleAccess> CreateRoleAccess(string roleId)
        {
            var role = await _roleManager.GetRoleAsync(roleId, OrgEntityHeader, UserEntityHeader);
            return new RoleAccess()
            {
                Id = Guid.NewGuid().ToId(),
                CreatedBy = UserEntityHeader,
                Organization = OrgEntityHeader,
                CreationDate = DateTime.UtcNow.ToJSONString(),
                Role = EntityHeader.Create(roleId, role.Key, role.Name),
            };
        }
    }
}
