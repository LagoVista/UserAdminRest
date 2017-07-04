using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.PlatformSupport;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Managers;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.UserAdmin.Models.Orgs;
using LagoVista.UserAdmin.ViewModels.Organization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    /// <summary>
    /// Orgs Srevices
    /// </summary>
    [Authorize]
    public class OrgServicesController : LagoVistaBaseController
    {
        IAppUserManager _appUserManager;
        IOrganizationManager _orgManager;

        public OrgServicesController(IAppUserManager appUserManager, IOrganizationManager orgManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _appUserManager = appUserManager;
            _orgManager = orgManager;
        }


        /// <summary>
        /// Orgs Service - Get Orgs for User
        /// </summary>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/user/{userid}/orgs")]
        public async Task<ListResponse<OrgUser>> GetOrgForAccountAsync(String userid)
        {
            var orgAccount = await _orgManager.GetOrganizationsForUserAsync(userid, OrgEntityHeader, UserEntityHeader);

            return ListResponse<OrgUser>.Create(orgAccount);
        }

        /// <summary>
        /// Orgs Service - Add User to Org
        /// </summary>
        /// <param name="orgid"></param>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/org/{orgid}/{userid}/orgs")]
        public async Task<InvokeResult> AddAccountToOrgAsync(string orgid, String userid)
        {
            return await _orgManager.AddUserToOrgAsync(orgid, userid,OrgEntityHeader, UserEntityHeader);
        }


        /// <summary>
        /// Orgs Service - Get Users for Org
        /// </summary>
        /// <param name="orgid"></param>
        /// <returns></returns>
        [HttpGet("/api/org/{orgid}/users")]
        public async Task<ListResponse<OrgUser>> GetUserForOrgAsync(String orgid)
        {
            var orgAccount = await _orgManager.GetUsersForOrganizationsAsync(orgid, OrgEntityHeader, UserEntityHeader);

            return ListResponse<OrgUser>.Create(orgAccount);
        }

        /// <summary>
        /// Orgs Service - Add an Organization
        /// </summary>
        /// <param name="orgVM"></param>
        /// <returns></returns>
        [HttpPost("/api/org")]
        public async Task<InvokeResult> CreateOrgAsync([FromBody] CreateOrganizationViewModel orgVM)
        {
            await _orgManager.CreateNewOrganizationAsync(orgVM, UserEntityHeader);
            return InvokeResult.Success;
        }

        /// <summary>
        /// Orgs Service - Org Factory
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/org/factory")]
        public DetailResponse<CreateOrganizationViewModel> CreateOrgFactory()
        {
            var createOrgVM = new CreateOrganizationViewModel();

            return DetailResponse<CreateOrganizationViewModel>.Create(createOrgVM);
        }
    }
}
