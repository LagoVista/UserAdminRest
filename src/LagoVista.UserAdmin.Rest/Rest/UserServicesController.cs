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

namespace LagoVista.UserManagement.Rest
{
    /// <summary>
    /// User Services
    /// </summary>
    [Authorize]
    public class UserServicesController : LagoVistaBaseController
    {
        private readonly IAppUserManager _appUserManager;

        public UserServicesController(IAppUserManager appUserManager,  UserManager<AppUser> userManager, IAdminLogger adminLogger) : base(userManager, adminLogger)
        {
            _appUserManager = appUserManager;
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
        /// User Service - Get Currently Logged In User.
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/user")]
        public async Task<DetailResponse<UserInfo>> GetCurrentUser()
        {
            var appUser = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            //No need to send the password has down there, need to be careful when doing an update...
            appUser.PasswordHash = null;
            return DetailResponse<UserInfo>.Create(appUser.ToUserInfo());
        }


        /// <summary>
        /// User Service - Register a new user (sign-up)
        /// </summary>
        /// <param name="newUser"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("/api/user/register")]
        public Task<InvokeResult<AuthResponse>> CreateNewAsync([FromBody] RegisterUser newUser)
        {
            return _appUserManager.CreateUserAsync(newUser);
        }
    }
}