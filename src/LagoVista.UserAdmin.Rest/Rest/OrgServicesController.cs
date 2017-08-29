using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.PlatformSupport;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Managers;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.UserAdmin.Models.Orgs;
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.UserAdmin.ViewModels.Organization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using LagoVista.Core.Authentication.Models;
using LagoVista.UserAdmin.Interfaces.Repos.Security;
using LagoVista.Core.Models;

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
        IAuthTokenManager _authTokenManager;
        ISignInManager _signInManager;

        public OrgServicesController(IAppUserManager appUserManager, ISignInManager signInManager, IAuthTokenManager authTokenManager, IOrganizationManager orgManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _appUserManager = appUserManager;
            _orgManager = orgManager;
            _authTokenManager = authTokenManager;
            _signInManager = signInManager;
        }


        /// <summary>
        /// Orgs Service - Get Orgs for User
        /// </summary>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/user/{userid}/orgs")]
        public async Task<ListResponse<OrgUser>> GetOrgsForUserAsync(string userid)
        {
            var orgsForUser = await _orgManager.GetOrganizationsForUserAsync(userid, OrgEntityHeader, UserEntityHeader);
            return ListResponse<OrgUser>.Create(orgsForUser);
        }

        /// <summary>
        /// Orgs Service - Get Users for Org
        /// </summary>
        /// <param name="orgid"></param>
        /// <returns></returns>
        [HttpGet("/api/org/{orgid}/users")]
        public async Task<ListResponse<UserInfoSummary>> GetUserForOrgAsync(string orgid)
        {
            var orgUsers = await _orgManager.GetUsersForOrganizationsAsync(orgid, OrgEntityHeader, UserEntityHeader);
            return ListResponse<UserInfoSummary>.Create(orgUsers);
        }

        /// <summary>
        /// Orgs Service - Add User to Org
        /// </summary>
        /// <param name="orgid"></param>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/org/{orgid}/{userid}/orgs")]
        public async Task<InvokeResult> AddAccountToOrgAsync(string orgid, string userid)
        {
            return await _orgManager.AddUserToOrgAsync(orgid, userid,OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Orgs Service - Add an Organization
        /// </summary>
        /// <param name="orgVM"></param>
        /// <returns></returns>
        [HttpPost("/api/org")]
        public Task<InvokeResult> CreateOrgAsync([FromBody] CreateOrganizationViewModel orgVM)
        {
            return _orgManager.CreateNewOrganizationAsync(orgVM, UserEntityHeader);
        }


        /// <summary>
        /// Orgs Service - Return Organization
        /// </summary>
        /// <param name="id">Organization Id</param>
        /// <returns></returns>
        [HttpGet("/api/org/{id}")]
        public async Task<DetailResponse<Organization>> GetOrgAsync(string id)
        {
            var org = await _orgManager.GetOrganizationAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<Organization>.Create(org);
        }

        /// <summary>
        /// Orgs Service - Return Currently Organization
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/org/current")]
        public async Task<DetailResponse<Organization>> GetCurrentOrgAsync()
        {
            var org = await _orgManager.GetOrganizationAsync(OrgEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<Organization>.Create(org);
        }


        /// <summary>
        /// Orgs Service - Org Factory
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/org/factory")]
        public DetailResponse<CreateOrganizationViewModel> CreateOrgFactory()
        {
            return DetailResponse<CreateOrganizationViewModel>.Create();
        }

        /// <summary>
        /// Orgs Service - Invite User to Join Org
        /// </summary>
        /// <param name="inviteUser"></param>
        /// <returns></returns>
        [HttpPost("/api/org/inviteuser/send")]
        public  Task<InvokeResult<Invitation>> InviteToOrgAsync([FromBody] InviteUser inviteUser)
        {
            return _orgManager.InviteUserAsync(inviteUser, OrgEntityHeader, UserEntityHeader);
        }       

        /// <summary>
        /// Orgs Service - Accept Invitation
        /// </summary>
        /// <param name="inviteid"></param>
        /// <returns></returns>
        [HttpPost("/api/org/inviteuser/accept/{inviteid}")]
        public async Task<InvokeResult> AcceptInvitationAsync(string inviteid)
        {
            return await _orgManager.AcceptInvitationAsync(inviteid, OrgEntityHeader, UserEntityHeader);
        }


        /// <summary>
        /// Orgs Service - Switch To New Org
        /// </summary>
        /// <param name="authRequest"></param>
        /// <returns></returns>
        [HttpPost("/api/org/change")]
        public Task<InvokeResult<AuthResponse>> SwitchOrgs([FromBody] AuthRequest authRequest)
        {
            return _authTokenManager.RefreshTokenGrantAsync(authRequest);
        }
    }
}
