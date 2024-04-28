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
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.Core.Exceptions;
using LagoVista.Core;
using LagoVista.UserAdmin.Models.Auth;

namespace LagoVista.UserAdmin.Rest
{
	/// <summary>
	/// Orgs Services
	/// </summary>
	[Authorize]
	public class OrgServicesController : LagoVistaBaseController
	{
		IOrganizationManager _orgManager;
		IAuthTokenManager _authTokenManager;
		ISignInManager _signInManager;

		public OrgServicesController(IAppUserManager appUserManager, ISignInManager signInManager, IAuthTokenManager authTokenManager, IOrganizationManager orgManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
		{
			_orgManager = orgManager;
			_authTokenManager = authTokenManager;
			_signInManager = signInManager;
		}


		/// <summary>
		/// Orgs Service - Get Orgs for User
		/// </summary>
		/// <returns></returns>
		[HttpGet("/api/user/orgs")]
		public async Task<ListResponse<OrgUser>> GetOrgsForUserAsync()
		{
			var orgsForUser = await _orgManager.GetOrganizationsForUserAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
			return ListResponse<OrgUser>.Create(orgsForUser);
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
		/// Orgs Service - Check if Namespace in use
		/// </summary>
		/// <param name="orgnamespace"></param>
		/// <returns></returns>
		[HttpGet("/api/org/namespace/{orgnamespace}/canuse")]
		public async Task<InvokeResult> CheckNameSpaceInUseAsync(string orgnamespace)
		{
			var inUse = await _orgManager.QueryOrgNamespaceInUseAsync(orgnamespace);
			if (inUse)
			{
				var errMessage = LagoVista.UserAdmin.Models.Resources.UserAdminResources.Organization_NamespaceInUse.Replace(LagoVista.UserAdmin.Resources.Tokens.NAMESPACE, orgnamespace);
				return InvokeResult.FromErrors(new ErrorMessage(errMessage));
			}
			else
			{
				return InvokeResult.Success;
			}
		}

		/// <summary>
		/// Orgs Service - Get Users for Org
		/// </summary>
		/// <returns></returns>
		[HttpGet("/api/users")]
		public async Task<ListResponse<UserInfoSummary>> GetUserForOrgAsync()
		{
			var orgUsers = await _orgManager.GetUsersForOrganizationsAsync(OrgEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
			return ListResponse<UserInfoSummary>.Create(orgUsers);
		}


		/// <summary>
		/// Orgs Service - Get Users for Org
		/// </summary>
		/// <returns></returns>
		[HttpGet("/api/users/active")]
		public async Task<ListResponse<UserInfoSummary>> GetActiveUserForOrgAsync()
		{
			var orgUsers = await _orgManager.GetActiveUsersForOrganizationsAsync(OrgEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
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
			return await _orgManager.AddUserToOrgAsync(orgid, userid, OrgEntityHeader, UserEntityHeader);
		}

		/// <summary>
		/// Orgs Service - Add an Organization
		/// </summary>
		/// <param name="orgVM"></param>
		/// <returns></returns>
		[HttpPost("/api/org")]
		public async Task<InvokeResult> CreateOrgAsync([FromBody] CreateOrganizationViewModel orgVM)
		{
			var org = await _orgManager.CreateNewOrganizationAsync(orgVM, UserEntityHeader);

			var currentUser = await this.GetCurrentUserAsync();

			if (currentUser == null)
			{
				throw new RecordNotFoundException("AppUser", UserEntityHeader.Id + $"{UserEntityHeader.Id}");
			}

			if (currentUser.OwnerOrganization == null)
			{
				await _signInManager.RefreshUserLoginAsync(currentUser);
			}

			//            await _signInManager.SignInAsync(currentUser);
			return org.ToInvokeResult();
		}

		/// <summary>
		/// Orgs Service - See if the current org has been initialized.
		/// </summary>
		/// <returns></returns>
		[HttpGet("/api/org/initialized")]
		public async Task<InvokeResult<Boolean>> IsCUrrentOrgIninitalized()
		{
			var org = await _orgManager.GetOrganizationAsync(OrgEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
			return InvokeResult<Boolean>.Create(org.InitializationCompleted);
		}

		/// <summary>
		/// Orgs Service - See if the current org has been initialized.
		/// </summary>
		/// <returns></returns>
		[HttpGet("/api/org/initialized/true")]
		public async Task<InvokeResult> SetCurrentOrgIninitalized()
		{
			var org = await _orgManager.GetOrganizationAsync(OrgEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
			if (!org.InitializationCompleted)
			{
				org.InitializationCompleted = true;
				org.InitializationCompletedDate = DateTime.UtcNow.ToJSONString();
				org.InitializationCompletedBy = UserEntityHeader;
				return await _orgManager.UpdateOrganizationAsync(org, OrgEntityHeader, UserEntityHeader);
			}

			return InvokeResult.Success;
		}



		/// <summary>
		/// Orgs Service - Add an Organization
		/// </summary>
		/// <param name="org"></param>
		/// <returns></returns>
		[HttpPut("/api/org")]
		public async Task<InvokeResult> UpdateOrgAsync([FromBody] Organization org)
		{
			return await _orgManager.UpdateOrganizationAsync(org, OrgEntityHeader, UserEntityHeader);
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
		[OrgAdmin]
		[HttpPost("/api/org/inviteuser/send")]
		public Task<InvokeResult<Invitation>> InviteToOrgAsync([FromBody] InviteUser inviteUser)
		{
			return _orgManager.InviteUserAsync(inviteUser, OrgEntityHeader, UserEntityHeader);
		}


		/// <summary>
		/// Orgs Service - Invitation Factory
		/// </summary>
		/// <returns></returns>
		[HttpGet("/api/org/invitation/factory")]
		public DetailResponse<InviteUserViewModel> CreateOrgInvitationFactory()
		{
			return DetailResponse<InviteUserViewModel>.Create();
		}

		/// <summary>
		/// Orgs Service - Get Invitations
		/// </summary>
		/// <returns></returns>
		[OrgAdmin]
		[HttpGet("/api/org/invitations")]
		public Task<ListResponse<Invitation>> GetInvitationsAsync()
		{
			return _orgManager.GetActiveInvitationsForOrgAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
		}

		/// <summary>
		/// Orgs Service - Get Invitation
		/// </summary>
		/// <param name="invitationid"></param>
		/// <returns></returns>
		[AllowAnonymous]
		[HttpGet("/api/org/invitation/{invitationid}")]
		public Task<Invitation> GetInvitationAsync(string invitationid)
		{
			return _orgManager.GetInvitationAsync(invitationid);
		}

		/// <summary>
		/// Orgs Service - Get Invitation
		/// </summary>
		/// <param name="invitationid"></param>
		/// <returns></returns>
		[AllowAnonymous]
		[HttpGet("/api/org/invitation/form/{invitationid}")]
		public async Task<DetailResponse<InviteUserViewModel>> GetInvitationFormAsync(string invitationid)
		{
			var rawData = await _orgManager.GetInvitationAsync(invitationid);
			var model = new InviteUserViewModel { Email = rawData.Email, Message = rawData.Message, Name = rawData.Name };
			return DetailResponse<InviteUserViewModel>.Create(model);
		}

		/// <summary>
		/// Orgs Service - Revoke Invitation
		/// </summary>
		/// <param name="inviteId">Invitation Id</param>
		/// <returns></returns>
		[OrgAdmin]
		[HttpDelete("/api/org/invitation/{inviteId}")]
		public Task<InvokeResult> RevokeInvitationAsync(string inviteId)
		{
			return _orgManager.RevokeInvitationAsync(inviteId, OrgEntityHeader, UserEntityHeader);
		}

		/// <summary>
		/// Orgs Service - Resend Invitation
		/// </summary>
		/// <param name="inviteId">Invitation Id</param>
		/// <returns></returns>
		[OrgAdmin]
		[HttpGet("/api/org/invitation/{inviteId}/resend")]
		public Task<InvokeResult> ResendInvitationAsync(string inviteId)
		{
			return _orgManager.ResendInvitationAsync(inviteId, OrgEntityHeader, UserEntityHeader);
		}

		/// <summary>
		/// Orgs Service - Set Org Admin for User
		/// </summary>
		/// <returns></returns>
		[OrgAdmin]
		[HttpGet("/api/org/admin/{userId}/set")]
		public Task<InvokeResult> SetOrgAdmin(String userId)
		{
			return _orgManager.SetOrgAdminAsync(userId, OrgEntityHeader, UserEntityHeader);
		}

		/// <summary>
		/// Orgs Service - Clear Org Admin for User
		/// </summary>
		/// <returns></returns>
		[OrgAdmin]
		[HttpGet("/api/org/admin/{userId}/clear")]
		public Task<InvokeResult> ClearOrgAdmin(String userId)
		{
			return _orgManager.ClearOrgAdminAsync(userId, OrgEntityHeader, UserEntityHeader);
		}

		/// <summary>
		/// Orgs Service - Set appp builder privelages for user
		/// </summary>
		/// <returns></returns>
		[OrgAdmin]
		[HttpGet("/api/org/appbuilder/{userId}/set")]
		public Task<InvokeResult> SetAppBuilder(String userId)
		{
			return _orgManager.SetAppBuilderAsync(userId, OrgEntityHeader, UserEntityHeader);
		}

		/// <summary>
		/// Orgs Service - Clear app builder privelages for user
		/// </summary>
		/// <returns></returns>
		[OrgAdmin]
		[HttpGet("/api/org/appbuilder/{userId}/clear")]
		public Task<InvokeResult> ClearAppBuilder(String userId)
		{
			return _orgManager.ClearAppBuilderAsync(userId, OrgEntityHeader, UserEntityHeader);
		}


		/// <summary>
		/// Orgs Service - Check if user is app builder
		/// </summary>
		/// <returns></returns>
		[OrgAdmin]
		[HttpGet("/api/org/admin/{userId}")]
		public async Task<InvokeResult<bool>> IsAppBuilder(String userId)
		{
			return InvokeResult<bool>.Create(await _orgManager.IsUserAppBuildernAsync(OrgEntityHeader.Id, userId));
		}


		/// <summary>
		/// Orgs Service - Check if Invitation is Still Available
		/// </summary>
		/// <param name="inviteid"></param>
		/// <returns></returns>
		[AllowAnonymous]
		[HttpGet("/api/org/inviteuser/{inviteid}/isavailable")]
		public async Task<bool> GetIsInviteActiveAsync(string inviteid)
		{
			return await _orgManager.GetIsInvigationActiveAsync(inviteid);
		}


		/// <summary>
		/// Orgs Service - Switch To New Org
		/// </summary>
		/// <param name="authRequest"></param>
		/// <returns></returns>
		[HttpPost("/api/org/change")]
		public async Task<InvokeResult<AuthResponse>> SwitchOrgs([FromBody] AuthRequest authRequest)
		{
			var result = await _authTokenManager.RefreshTokenGrantAsync(authRequest);
			if (result.Successful)
			{
				var currentUser = await GetCurrentUserAsync();
				await _signInManager.SignInAsync(currentUser);
			}

			return result;
		}

		/// <summary>
		/// Orgs Service - Switch To New Org
		/// </summary>
		/// <param name="orgid"></param>
		/// <returns></returns>
		[HttpGet("/api/org/{orgid}/change")]
		public async Task<InvokeResult<AppUser>> SwitchOrgs(string orgid)
		{
			var result = await _orgManager.ChangeOrgsAsync(orgid, OrgEntityHeader, UserEntityHeader);
			if (result.Successful)
			{
				result.Result.PasswordHash = null;
				await _signInManager.SignInAsync(result.Result);
			}

			return result;
		}
	}

	[Authorize]
	[SystemAdmin]
	public class SysAdminOrgServicesController : LagoVistaBaseController
	{
		IOrganizationManager _orgManager;
		IAuthTokenManager _authTokenManager;
		ISignInManager _signInManager;
		IAppUserManager _appUserManager;

		public SysAdminOrgServicesController(IAppUserManager appUserManager, ISignInManager signInManager, IAuthTokenManager authTokenManager, IOrganizationManager orgManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
		{
			_orgManager = orgManager;
			_authTokenManager = authTokenManager;
			_signInManager = signInManager;
			_appUserManager = appUserManager;
		}

		[HttpGet("/sys/api/orgs/all")]
		public Task<ListResponse<OrganizationSummary>> GetAllOrgsAsync()
		{
			return _orgManager.GetAllOrgsAsync(OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
		}

		/// <summary>
		/// Orgs Service - Get Users for Org
		/// </summary>
		/// <returns></returns>
		[HttpGet("/sys/api/org/{orgid}/users")]
		public async Task<ListResponse<UserInfoSummary>> GetUserForOrgAsync(string orgid)
		{
			var orgUsers = await _orgManager.GetUsersForOrganizationsAsync(orgid, OrgEntityHeader, UserEntityHeader);
			return ListResponse<UserInfoSummary>.Create(orgUsers);
		}


		[HttpGet("/sys/api/users/withoutorgs")]
		public Task<ListResponse<UserInfoSummary>> GetUsersWithoutOrgAsync()
		{
			return _appUserManager.GetUsersWithoutOrgsAsync(UserEntityHeader, GetListRequestFromHeader());
		}


		[HttpGet("/sys/api/org/{id}/ownedobjects")]
		public Task<ListResponse<OwnedObject>> GetOwnedObjectsAsync(string id)
		{
			return _orgManager.GetOwnedObjectsForOrgAsync(id, GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
		}


		[HttpDelete("/sys/api/user/{id}")]
		public Task<InvokeResult> DeleteUserAsync(string id)
		{
			return _appUserManager.DeleteUserAsync(id, OrgEntityHeader, UserEntityHeader);
		}

		[HttpDelete("/sys/api/org/{id}")]
		public Task<InvokeResult> DeleteOrgAsync(string id)
		{
			return _orgManager.DeleteOrgAsync(id, OrgEntityHeader, UserEntityHeader);
		}
	}
}
