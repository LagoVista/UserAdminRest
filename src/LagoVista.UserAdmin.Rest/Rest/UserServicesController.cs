using LagoVista.IoT.Web.Common.Controllers;
using Microsoft.AspNetCore.Authorization;
using System;
using LagoVista.Core.PlatformSupport;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using LagoVista.UserAdmin.Managers;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.Core.Validation;
using LagoVista.UserAdmin.ViewModels.Users;
using LagoVista.UserAdmin.ViewModels.Organization;
using LagoVista.UserAdmin.Models.Orgs;

namespace LagoVista.UserManagement.Rest
{
    /// <summary>
    /// User Services
    /// </summary>
    [Authorize]
    public class UserServicesController : LagoVistaBaseController
    {
        private readonly IAppUserManager _appUserManager;
        private readonly IOrganizationManager _orgManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;

        public UserServicesController(IAppUserManager appUserManager, IOrganizationManager orgManager, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager,  IAdminLogger logger) : base(userManager, logger)
        {
            _appUserManager = appUserManager;
            _orgManager = orgManager;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        /// <summary>
        /// User Service - Get by Id
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
        /// User Service - Get by User Name (generally email)
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/user")]
        public async Task<DetailResponse<UserInfo>> GetCurrentUser()
        {
            var appUser = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
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
        public async Task<InvokeResult<AppUser>> CreateNewAsync([FromBody] RegisterViewModel newUser)
        {
            var validationResult = Validator.Validate(newUser, Actions.Create);
            if(!validationResult.Successful)
            {
                var failedValidationResult = new InvokeResult<AppUser>();
                failedValidationResult.Concat(validationResult);
                return failedValidationResult;
            }

            var lagoVistaUser = new AppUser(newUser.Email, $"{newUser.FirstName} {newUser.LastName}")
            {
                FirstName = newUser.FirstName,
                LastName = newUser.LastName,
            };

            var identityResult = await base.UserManager.CreateAsync(lagoVistaUser, newUser.Password);
            if (identityResult.Succeeded)
            {
                await _signInManager.SignInAsync(lagoVistaUser, isPersistent: false);
                return new InvokeResult<AppUser>() { Result = lagoVistaUser };
            }
            else
            {
                var result = new InvokeResult<AppUser>();
                foreach(var err in identityResult.Errors)
                {
                    result.Errors.Add(new ErrorMessage(err.Code, err.Description));
                }

                return result;
            }
        }

        /// <summary>
        /// Invite User - Invite New User
        /// </summary>
        /// <param name="inviteViewModel"></param>
        /// <returns></returns>
        [HttpPost("/api/user/invite")]
        public Task<InvokeResult<Invitation>> InviteUser([FromBody] InviteUserViewModel inviteViewModel)
        {
            return _orgManager.InviteUserAsync(inviteViewModel, OrgEntityHeader, UserEntityHeader);
        }
    }
}