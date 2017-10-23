using LagoVista.IoT.Web.Common.Controllers;
using Microsoft.AspNetCore.Authorization;
using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using LagoVista.UserAdmin.Managers;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.Core.Validation;
using LagoVista.Core.Authentication.Models;
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.Core;

namespace LagoVista.UserManagement.Rest
{
    /// <summary>
    /// User Services
    /// </summary>
    [Authorize]
    public class UserServicesController : LagoVistaBaseController
    {
        private readonly IAppUserManager _appUserManager;
        private readonly IUserManager _usrManager; /* TODO: OK TOO MANY USER MANGERS, may need refactoring */
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IOrganizationManager _orgManager;

        public UserServicesController(IAppUserManager appUserManager, IOrganizationManager orgManager, IUserManager usrManager, SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, IAdminLogger adminLogger) : base(userManager, adminLogger)
        {
            _appUserManager = appUserManager;
            _usrManager = usrManager;
            _signInManager = signInManager;
            _orgManager = orgManager;
        }

        /// <summary>
        /// User Service - Get a User By ID
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/user/{id}")]
        public async Task<DetailResponse<UserInfo>> GetUserAsync(String id)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<UserInfo>.Create(appUser.ToUserInfo());
        }

        /// <summary>
        /// User Service - Get User by Email
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [HttpGet("/api/user")]
        public async Task<DetailResponse<UserInfo>> GetUserByEmailAsync(String email)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(email, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<UserInfo>.Create(appUser.ToUserInfo());
        }


        /// <summary>
        /// User Service - Enable/Disable preview status for user
        /// </summary>
        /// <param name="id"></param>
        /// <param name="status"></param>
        /// <returns></returns>
        [HttpGet("/api/user/{id}/preview/{status}")]
        public async Task<InvokeResult> SetPreviewStatusAsync(String id, bool status)
        {
            return await _usrManager.SetPreviewUserStatusAsync(id, status, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Get Currently Logged In User.
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/user")]
        public async Task<DetailResponse<UserInfo>> ReturnCurrentUserAsync()
        {
            var appUser = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            //No need to send the password has down there, need to be careful when doing an update...
            return DetailResponse<UserInfo>.Create(appUser.ToUserInfo());
        }

        /// <summary>
        /// User Service - Update User
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPut("/api/user")]
        public Task<InvokeResult> UpdateCurrentUserAsync([FromBody] UserInfo user)
        {
            return _appUserManager.UpdateUserAsync(user, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Register a new user (sign-up)
        /// </summary>
        /// <param name="newUser"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("/api/user/register")]
        public async Task<InvokeResult<AuthResponse>> CreateNewAsync([FromBody] RegisterUser newUser)
        {
            var result = await _appUserManager.CreateUserAsync(newUser);
            if (!String.IsNullOrEmpty(newUser.InviteId) && result.Successful)
            {
                await _orgManager.AcceptInvitationAsync(newUser.InviteId, result.Result.User.Id);
                var user = await _appUserManager.GetUserByIdAsync(result.Result.User.Id, OrgEntityHeader, result.Result.User);
                await _signInManager.SignInAsync(user, false);
            }

            return result;
        }

        /// <summary>
        /// User Service - Set as System Admin (requires system admin)
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [SystemAdmin]
        [HttpGet("/api/user/sysadmin/{id}/set")]
        public Task<InvokeResult> SetAsSystemAdmin(string id)
        {
            return _usrManager.SetSystemAdminAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Clear as System Admin (requires system admin)
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [SystemAdmin]
        [HttpGet("/api/user/sysadmin/{id}/clear")]
        public Task<InvokeResult> ClearSystemAdmin(string id)
        {
            return _usrManager.ClearSystemAdminAsync(id, OrgEntityHeader, UserEntityHeader);
        }
    }
}