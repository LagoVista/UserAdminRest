using LagoVista.Core;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
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
    [Authorize]
    public class RoleService : LagoVistaBaseController
    {
        private readonly IUserRoleManager _roleManager;

        public RoleService(IUserRoleManager userRoleManager,  UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _roleManager = userRoleManager ?? throw new ArgumentNullException(nameof(userRoleManager));
        }

        [HttpGet("/api/sys/roles")]
        public Task<List<RoleSummary>> GetRolesAsync()
        {
            return _roleManager.GetRolesAsync(OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sys/role/{id}")]
        public async Task<DetailResponse<Role>> GetRolesAsync(string id)
        {
            var role = await  _roleManager.GetRoleAsync(id, OrgEntityHeader, UserEntityHeader);
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
    }
}
