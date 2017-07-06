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
using LagoVista.UserAdmin.Interfaces.Repos.Security;
using LagoVista.Core.Authentication.Models;
using LagoVista.UserAdmin.Resources;

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
        private readonly IAuthTokenManager _authTokenManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly IAdminLogger _adminLogger;

        public UserServicesController(IAppUserManager appUserManager, IAuthTokenManager authTokenManager, IOrganizationManager orgManager, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IAdminLogger adminLogger) : base(userManager, adminLogger)
        {
            _appUserManager = appUserManager;
            _orgManager = orgManager;
            _authTokenManager = authTokenManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _adminLogger = adminLogger;
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
        public async Task<InvokeResult<AuthResponse>> CreateNewAsync([FromBody] RegisterViewModel newUser)
        {
            var validationResult = Validator.Validate(newUser, Actions.Create);
            if (!validationResult.Successful)
            {
                var failedValidationResult = new InvokeResult<AuthResponse>();
                failedValidationResult.Concat(validationResult);
                return failedValidationResult;
            }

            if (String.IsNullOrEmpty(newUser.AppId))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserServicesController_CreateNewAsync", UserAdminErrorCodes.AuthMissingAppId.Message);
                return InvokeResult<AuthResponse>.FromErrors(UserAdminErrorCodes.AuthMissingAppId.ToErrorMessage());
            }

            if (String.IsNullOrEmpty(newUser.InstallationId))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserServicesController_CreateNewAsync", UserAdminErrorCodes.AuthMissingInstallationId.Message);
                return InvokeResult<AuthResponse>.FromErrors(UserAdminErrorCodes.AuthMissingInstallationId.ToErrorMessage());
            }

            if (String.IsNullOrEmpty(newUser.ClientType))
            {
                _adminLogger.AddCustomEvent(Core.PlatformSupport.LogLevel.Error, "UserServicesController_CreateNewAsync", UserAdminErrorCodes.AuthMissingClientType.Message);
                return InvokeResult<AuthResponse>.FromErrors(UserAdminErrorCodes.AuthMissingClientType.ToErrorMessage());
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
                var authRequest = new AuthRequest()
                {
                    AppId = newUser.AppId,
                    DeviceId = newUser.DeviceId,
                    InstallationId = newUser.InstallationId,
                    ClientType = newUser.ClientType,
                    GrantType = "password",
                    Email = newUser.Email,
                    UserName = newUser.Email,
                    Password = newUser.Password,
                };

                var tokenResponse = await _authTokenManager.AuthAsync(authRequest);
                if (tokenResponse.Successful)
                {
                    return InvokeResult<AuthResponse>.Create(tokenResponse.Result);
                }
                else
                {
                    var failedValidationResult = new InvokeResult<AuthResponse>();
                    failedValidationResult.Concat(tokenResponse);
                    return failedValidationResult;
                }
            }
            else
            {
                var result = new InvokeResult<AuthResponse>();
                foreach (var err in identityResult.Errors)
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