using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{

    [Authorize]
    public class UserRoleService : LagoVistaBaseController
    {
        private readonly IUserRoleManager _userRoleManager;

        public UserRoleService(IUserRoleManager userRoleManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _userRoleManager = userRoleManager ?? throw new ArgumentNullException(nameof(userRoleManager));
        }

        [HttpGet("/app/user/{userid}/role/{roleid}/grant")]
        public Task<InvokeResult<UserRole>> GrantAsync(string userid, string roleid)
        {
            return _userRoleManager.GrantUserRoleAsync(userid, roleid, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/app/user/{userid}/roles/grant")]
        public async Task<InvokeResult<List<UserRole>>> GrantAsync([FromBody] List<string> roles, string userid)
        {
            var results = new InvokeResult<List<UserRole>>() { Result = new List<UserRole>() };
           var grantedRoles = await _userRoleManager.GrantUserRolesAsync(userid, roles, OrgEntityHeader, UserEntityHeader);
            foreach(var result in grantedRoles)
            {
                if (result.Successful)
                {
                    results.Result.Add(result.Result);
                }
                else
                {
                    result.Errors.AddRange(result.Errors);
                }
            }

            return results;
        }

        [HttpDelete("/app/user/role/revoke/{userroleid}")]
        public Task<InvokeResult> RevokeAsync(string userroleid)
        {
            return _userRoleManager.RevokeUserRoleAsync(userroleid, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/app/user/{userid}/roles")]
        public Task<List<UserRole>> GetRolesForUserAsync(string userid)
        {
            return _userRoleManager.GetRolesForUserAsync(userid, OrgEntityHeader, UserEntityHeader);
        }


        [HttpGet("/app/user/roles")]
        public Task<List<UserRole>> GetRolesForUserAsync()
        {
            return _userRoleManager.GetRolesForUserAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
        }
    }
}
