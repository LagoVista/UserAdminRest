using LagoVista.IoT.Web.Common.Controllers;
using Microsoft.AspNetCore.Authorization;
using System;
using LagoVista.Core.PlatformSupport;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using LagoVista.UserAdmin.Managers;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.UserAdmin.Models.Account;

namespace LagoVista.UserManagement.Rest
{
    /// <summary>
    /// User Services
    /// </summary>
    [Authorize]
    [Route("api/v1/user")]
    public class UserServices : LagoVistaBaseController
    {
        IAppUserManager _appUserManager;
        public UserServices(IAppUserManager appUserManager, UserManager<AppUser> userManager, ILogger logger) : base(userManager, logger)
        {
            _appUserManager = appUserManager;
        }

        /// <summary>
        /// User Service - Get by Id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("{id}")]
        public async Task<DetailResponse<AppUser>> GetUserAsync(String id)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(id, UserEntityHeader);
            appUser.PasswordHash = null;
            return DetailResponse<AppUser>.Create(appUser);
        }

        /// <summary>
        /// User Service - Get by User Name (generally email)
        /// </summary>
        /// <returns></returns>
        [HttpGet()]
        public async Task<DetailResponse<AppUser>> GetCurrentUser()
        {
            var appUser = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, UserEntityHeader);
            appUser.PasswordHash = null;
            return DetailResponse<AppUser>.Create(appUser);
        }
    }
}