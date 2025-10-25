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
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.UserAdmin.Interfaces.Managers;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http;
using LagoVista.UserAdmin.ViewModels.Users;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.UserAdmin.Repos.Repos.Account;
using LagoVista.UserAdmin.Interfaces;
using LagoVista.Core.Interfaces;
using System.Diagnostics;
using LagoVista.MediaServices.Interfaces;
using System.Linq;
using LagoVista.IoT.Billing.Managers;
using LagoVista.IoT.Billing.Models;
using RingCentral;
using LagoVista.Core;
using LagoVista.Core.Exceptions;
using LagoVista.UserAdmin.Models.Security;

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
        private readonly IUserFavoritesManager _userFavoritesManager;
        private readonly IMostRecentlyUsedManager _mruManager;
        private readonly IAppUserInboxManager _appUserInboxManager;
        private readonly IAppConfig _appConfig;
        private readonly IAuthenticationLogManager _authLogManager;
        private readonly IMediaServicesManager _mediaServicesManager;
        private readonly ITimeZoneServices _timeZoneServices;
        private readonly ILocalizationService _localizationService;
        private readonly ICustomerManager _customerManager;
        private readonly IUserRegistrationManager _userRegistrationManager;

        public UserServicesController(IAppUserManager appUserManager, IUserRegistrationManager userRegistrationManager, IOrganizationManager orgManager, IUserFavoritesManager userFavoritesManager, ITimeZoneServices timeZoneServices, IUserManager usrManager, IAppUserInboxManager appUserInboxManager, IMediaServicesManager mediaServicesManager,
          ILocalizationService localizationService, ICustomerManager customerManager, IAuthenticationLogManager authLogManager, IAppConfig appConfig, IMostRecentlyUsedManager mruManager, SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, IAdminLogger adminLogger) : base(userManager, adminLogger)
        {
            _appUserManager = appUserManager;
            _usrManager = usrManager;
            _signInManager = signInManager;
            _orgManager = orgManager;
            _userFavoritesManager = userFavoritesManager;
            _mruManager = mruManager;
            _appUserInboxManager = appUserInboxManager;
            _appConfig = appConfig;
            _authLogManager = authLogManager;
            _mediaServicesManager = mediaServicesManager;
            _customerManager = customerManager;
            _localizationService = localizationService;
            _timeZoneServices = timeZoneServices;
            _userRegistrationManager = userRegistrationManager;
        }

        /// <summary>
        /// User Service - Get a User By ID
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/user/{id}")]
        public async Task<DetailResponse<AppUser>> GetUserAsync(String id)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(id, OrgEntityHeader, UserEntityHeader);
            var form = DetailResponse<AppUser>.Create(appUser);
            form.View[nameof(AppUser.TimeZone).CamelCase()].Options = _timeZoneServices.GetTimeZoneEnumOptions();
            form.View[nameof(AppUser.Language).CamelCase()].Options = _localizationService.GetCultureEnumOptions();
            return form;
        }

        void AuthorizeUserEditing(AppUser user)
        {
            if (IsSysAdmin)
                return;

            if(IsOrgAdmin && user.Organizations.Any(org => org.Id == OrgEntityHeader.Id))
                return;

            throw new NotAuthorizedException("You are not authorized to edit this user.  You must be logged in to an organization that this user is a part of.");
        }

        [SystemAdmin]
        [HttpGet("/api/sys/user/search")]
        public async Task<ListResponse<UserInfoSummary>> SearchUsers([FromQuery] string email, [FromQuery] string firstname, [FromQuery] string lastname)
        {
            return await _appUserManager.SearchUsersAsync(email, firstname, lastname, OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        /// <summary>
        /// User Service - force the user to have a confirmed email address.
        /// </summary>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/user/{userid}/email/confirm")]
        public async Task<InvokeResult<AppUser>> ConfirmUserEmaililAsync(String userid)
        {
       
            var appUser = await _appUserManager.GetUserByIdAsync(userid, OrgEntityHeader, UserEntityHeader);
            AuthorizeUserEditing(appUser);

            appUser.EmailConfirmed = true;
            appUser.SetLastUpdatedFields(UserEntityHeader);
            appUser.AddChange(nameof(AppUser.EmailConfirmed), false.ToString(), true.ToString());
            await _appUserManager.UpdateUserAsync(appUser, OrgEntityHeader, UserEntityHeader);
            return InvokeResult<AppUser>.Create(appUser);
        }

        /// <summary>
        /// User Service - force the user to have a confirmed email address.
        /// </summary>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/user/{userid}/email/confirm/send")]
        public async Task<InvokeResult<AppUser>> SendConfirmUserEmaililAsync(String userid)
        {

            var appUser = await _appUserManager.GetUserByIdAsync(userid, OrgEntityHeader, UserEntityHeader);
            AuthorizeUserEditing(appUser);

            appUser.EmailConfirmed = true;
            appUser.SetLastUpdatedFields(UserEntityHeader);
            appUser.AddChange(nameof(AppUser.EmailConfirmed), false.ToString(), true.ToString());
            await _appUserManager.UpdateUserAsync(appUser, OrgEntityHeader, UserEntityHeader);
            return InvokeResult<AppUser>.Create(appUser);
        }

        /// <summary>
        /// User Service - force the user to have a confirmed email address.
        /// </summary>
        /// <param name="userid"></param>
        /// <param name="logintype"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/user/{userid}/logintype/{logintype}")]
        public async Task<InvokeResult<AppUser>> SetLoginType(string userid, String logintype)
        {
            if (Enum.TryParse<LoginTypes>(logintype, true, out var loginType))
            {
                var appUser = await _appUserManager.GetUserByIdAsync(userid, OrgEntityHeader, UserEntityHeader);
                AuthorizeUserEditing(appUser);

                appUser.SetLastUpdatedFields(UserEntityHeader);
                appUser.AddChange(nameof(AppUser.LoginType), appUser.LoginType.ToString(), loginType.ToString());
                appUser.LoginType = loginType;
                await _appUserManager.UpdateUserAsync(appUser, OrgEntityHeader, UserEntityHeader);
                return InvokeResult<AppUser>.Create(appUser);
            }
            else
            {
                return InvokeResult<AppUser>.FromError($"Could not parse login type: {logintype}");
            }
        }

        [SystemAdmin]
        [HttpGet("/api/sys/user/{userid}/auth/log")]
        public async Task<ListResponse<AuthenticationLog>> GetUserAuthLogAsync(String userid)
        {
            return await _authLogManager.GetForUserIdAsync(userid, GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }


        [SystemAdmin]
        [HttpGet("/api/sys/user/email/auth/log")]
        public async Task<ListResponse<AuthenticationLog>> GetForUserEmailAsync([FromQuery] String email)
        {
            return await _authLogManager.GetForUserNameAsync(email, GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }


        /// <summary>
        /// User Service - force the user to have a confirmed phone number.
        /// </summary>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/user/{userid}/phone/confirm")]
        public async Task<InvokeResult< AppUser>> ConfirmUserPhoneAsync(String userid)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(userid, OrgEntityHeader, UserEntityHeader);
            AuthorizeUserEditing(appUser);

            appUser.PhoneNumberConfirmed = true;
            appUser.SetLastUpdatedFields(UserEntityHeader);
            appUser.AddChange(nameof(AppUser.PhoneNumberConfirmed), false.ToString(), true.ToString());
            await _appUserManager.UpdateUserAsync(appUser, OrgEntityHeader, UserEntityHeader);
            return InvokeResult<AppUser>.Create(appUser);
        }

        /// <summary>
        /// User Service - force the user to have a confirmed phone number.
        /// </summary>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/user/{userid}/phone/confirm/send")]
        public async Task<InvokeResult<AppUser>> SendConfirmUserPhoneAsync(String userid)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(userid, OrgEntityHeader, UserEntityHeader);
            AuthorizeUserEditing(appUser);

            appUser.PhoneNumberConfirmed = true;
            appUser.SetLastUpdatedFields(UserEntityHeader);
            appUser.AddChange(nameof(AppUser.PhoneNumberConfirmed), false.ToString(), true.ToString());
            await _appUserManager.UpdateUserAsync(appUser, OrgEntityHeader, UserEntityHeader);
            return InvokeResult<AppUser>.Create(appUser);
        }


        /// <summary>
        /// User Service - add user to org
        /// </summary>
        /// <param name="orgid"></param>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/org/{orgid}/user/{userid}/add")]
        public async Task<InvokeResult<AppUser>> AddUsertOrgAsync(string orgid, String userid)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(userid, OrgEntityHeader, UserEntityHeader);
            if (!IsSysAdmin)
                throw new NotAuthorizedException("Must be a system admin to add a user to organization.");

            await _orgManager.AddUserToOrgAsync(orgid, userid, OrgEntityHeader, UserEntityHeader);
            return InvokeResult<AppUser>.Create(appUser);
        }

        /// <summary>
        /// User Service - Get User by Email
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [HttpGet("/api/userbyemail")]
        public async Task<DetailResponse<UserInfo>> GetUserByEmailAsync(String email)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(email, OrgEntityHeader, UserEntityHeader);
            var form = DetailResponse<UserInfo>.Create(appUser.ToUserInfo());
            form.View[nameof(AppUser.TimeZone).CamelCase()].Options = _timeZoneServices.GetTimeZoneEnumOptions();
            return form;
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
        public async Task<DetailResponse<AppUser>> ReturnCurrentUserAsync()
        {
            var appUser = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            var form = DetailResponse<AppUser>.Create(appUser);
            form.View[nameof(AppUser.TimeZone).CamelCase()].Options = _timeZoneServices.GetTimeZoneEnumOptions();
            //No need to send the password has down there, need to be careful when doing an update...
            return form;
        }

        [SystemAdmin]
        [HttpGet("/sys/api/users/all")]
        public async Task<ListResponse<UserInfoSummary>> GetAllUsers(bool? emailconfirmed, bool? smsconfirmed)
        {
            return await _appUserManager.GetAllUsersAsync(emailconfirmed, smsconfirmed, OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        [SystemAdmin]
        [HttpGet("/sys/api/users/active")]
        public async Task<ListResponse<UserInfoSummary>> GetActiveUses()
        {
            return await _appUserManager.GetActiveUsersAsync(OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        [HttpGet("/api/users/welcome/show/{state}")]
        public async Task ShowWelcomeOnLogin(bool state)
        {
            var appUser = await _appUserManager.GetUserByIdAsync(UserEntityHeader.Id, OrgEntityHeader, UserEntityHeader);
            appUser.ShowWelcome = state;
            await _appUserManager.UpdateUserAsync(appUser.ToUserInfo(), OrgEntityHeader, UserEntityHeader);
        }

        [HttpDelete("/api/user")]
        public async Task<InvokeResult> DeleteUserByEmail(string username)
         {

            if (_appConfig.Environment == Environments.Production ||
                _appConfig.Environment == Environments.Staging)
                throw new NotSupportedException();

            var user = await _appUserManager.GetUserByUserNameAsync(username, OrgEntityHeader, UserEntityHeader);
            if (user == null)
            {
                await _authLogManager.AddAsync(UserAdmin.Models.Security.AuthLogTypes.DeleteUserFailed, userName: username, errors: $"Could not find a user with email address: {username}");
                return InvokeResult.FromError("Could not load user.");
            }

            var id = user.Id;
            var result = await _appUserManager.DeleteUserAsync(id, OrgEntityHeader, UserEntityHeader);
            if(result.Successful)
            {
                await _authLogManager.AddAsync(UserAdmin.Models.Security.AuthLogTypes.DeletedUser, userName: username, errors: result.ErrorMessage);
            }
            else
                await _authLogManager.AddAsync(UserAdmin.Models.Security.AuthLogTypes.DeleteUserFailed, userName: username, errors: result.ErrorMessage);

            return result;
        }

        /// <summary>
        /// User Service - Get User by Email
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpGet("/api/userbyemail/testing")]
        public async Task<DetailResponse<UserInfo>> TestGetUserByEmailAsync(String email)
        {
            if (_appConfig.Environment == Environments.Production ||
                _appConfig.Environment == Environments.Staging)
                throw new NotSupportedException();

            var appUser = await _appUserManager.GetUserByUserNameAsync(email, null, null);
            var form = DetailResponse<UserInfo>.Create(appUser.ToUserInfo());
            form.View[nameof(AppUser.TimeZone).CamelCase()].Options = _timeZoneServices.GetTimeZoneEnumOptions(); return form;
        }

        [HttpDelete("/api/user/{id}")]
        public async Task<InvokeResult> DeleteUser(string id)
        {
            if(id != UserEntityHeader.Id)
            {
                return InvokeResult.FromError("Can not remove a different user.");
            }

            var result = await _appUserManager.DeleteUserAsync(id, OrgEntityHeader, UserEntityHeader);
            if (id == UserEntityHeader.Id && result.Successful)
            {
                await _signInManager.SignOutAsync();
            }

            return result;
        }

        [SystemAdmin]
        [HttpDelete("/api/user/{id}/delete")]
        public async Task<InvokeResult> ForceDeleteUser(string id)
        {
            var result = await _appUserManager.DeleteUserAsync(id,  OrgEntityHeader, UserEntityHeader);
            if (id == UserEntityHeader.Id && result.Successful)
            {
                await _signInManager.SignOutAsync();
            }

            return result;
        }

        public static string GetClientIPAddress(HttpContext context)
        {
            string ip = string.Empty;
            if (!string.IsNullOrEmpty(context.Request.Headers["X-Forwarded-For"]))
            {
                ip = context.Request.Headers["X-Forwarded-For"];
            }
            else
            {
                ip = context.Request.HttpContext.Features.Get<IHttpConnectionFeature>().RemoteIpAddress.ToString();
            }
            return ip;
        }

        [HttpGet("/api/user/accepttc")]
        public Task<InvokeResult<AppUser>> AcceptTermsAndConditionsAsync()
        {
            var ipAddress = GetClientIPAddress(Request.HttpContext);

            return _appUserManager.AcceptTermsAndConditionsAsync(ipAddress, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Update User
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPut("/api/user")]
        public Task<InvokeResult> UpdateCurrentUserAsync([FromBody] CoreUserInfo user)
        {
            return _appUserManager.UpdateUserAsync(user, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Set Advacned Mode
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/user/mode/advanced")]
        public async Task<InvokeResult> SetUserModeAdvanced()
        {
            var user = await GetCurrentUserAsync();
            if (!user.AdvancedUser)
            {
                user.AdvancedUser = true;
                SetUpdatedProperties(user);
                return await _appUserManager.UpdateUserAsync(user, OrgEntityHeader, UserEntityHeader);
            }
            else
                return InvokeResult.Success;
        }

        /// <summary>
        /// User Service - Set Normal Mode
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/user/mode/normal")]
        public async Task<InvokeResult> SetUserModeNormal()
        {
            var user = await GetCurrentUserAsync();
            if (user.AdvancedUser)
            {
                user.AdvancedUser = false;
                SetUpdatedProperties(user);
                return await _appUserManager.UpdateUserAsync(user, OrgEntityHeader, UserEntityHeader);
            }
            return InvokeResult.Success;
        }

        /// <summary>
        /// User Service - Add Preference
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/user/preference/{key}/{value}")]
        public async Task<InvokeResult> AddPreference(string key, string value)
        {
            var user = await GetCurrentUserAsync();
            if (user.Preferences.ContainsKey(key))
                user.Preferences.Remove(key);

            SetUpdatedProperties(user);
            user.Preferences.Add(key, value);
            return await _appUserManager.UpdateUserAsync(user, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Set Normal Mode
        /// </summary>
        /// <returns></returns>
        [HttpDelete("/api/user/preference/{key}")]
        public async Task<InvokeResult> RemovePreference(string key)
        {
            var user = await GetCurrentUserAsync();
            if (user.Preferences.ContainsKey(key))
            {
                user.Preferences.Remove(key);

                SetUpdatedProperties(user);

                return await _appUserManager.UpdateUserAsync(user, OrgEntityHeader, UserEntityHeader);
            }

            return InvokeResult.Success;
        }

        /// <summary>
        /// Get Most Recent Used Items for User in an Organization.
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/mru")]
        public async Task<InvokeResult<MostRecentlyUsed>> GetMru()
        {
            return await _mruManager.GetMostRecentlyUsedAsync(OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Add a most recently used item.
        /// </summary>
        /// <param name="mruItem"></param>
        /// <returns></returns>
        [HttpPost("/api/mru/item")]
        public async Task<InvokeResult<MostRecentlyUsed>> AddMru([FromBody] MostRecentlyUsedItem mruItem)
        {
            Console.WriteLine("vvv Add MRU =============================================");
            var sw = Stopwatch.StartNew();
            var result = await _mruManager.AddMostRecentlyUsedAsync(mruItem, OrgEntityHeader, UserEntityHeader);
            result.Timings.Add(new ResultTiming() { Key = "totalprocessing", Ms = sw.Elapsed.TotalMilliseconds } );
            Console.WriteLine("^^^ Add MRU =============================================");
            return result;  
        }

        /// <summary>
        /// Clear most recently used items for a user in an organization.
        /// </summary>
        /// <returns></returns>
        [HttpDelete("/api/mru")]
        public async Task<InvokeResult<MostRecentlyUsed>> DeleteMru()
        {
            await  _mruManager.ClearMostRecentlyUsedAsync(OrgEntityHeader, UserEntityHeader);
            return InvokeResult<MostRecentlyUsed>.Create( new MostRecentlyUsed());
        }

        /// <summary>
        /// User Service - Add Media resources
        /// </summary>
        /// <param name="userid"></param>
        /// <param name="mediaResource"></param>
        /// <returns></returns>
        [HttpPost("/api/user/{userid}/mediaresource")]
        public Task<InvokeResult> UpdateCurrentUserAsync(string userid, [FromBody] EntityHeader mediaResource)
        {
            return _appUserManager.AddMediaResourceAsync(userid, mediaResource, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Update User (just basic info)
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPut("/api/user/coreinfo")]
        public Task<InvokeResult> UpdateUserAsync([FromBody] CoreUserInfo user)
        {
            return _appUserManager.UpdateUserAsync(user, OrgEntityHeader, UserEntityHeader);
        }   

        /// <summary>
        /// User Service - Get List of Favorites for current user.
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/user/favorites")]
        public async Task<InvokeResult<UserFavorites>> GetCurrentUserFavorites()
        {
            var result = await _userFavoritesManager.GetUserFavoritesAsync(UserEntityHeader, OrgEntityHeader);
            return InvokeResult<UserFavorites>.Create(result);
        }

        /// <summary>
        /// User Service - Add a new favorite.
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/user/favorite")]
        public async Task<InvokeResult<UserFavorites>> GetCurrentUserFavorites([FromBody] UserFavorite favorite)
        {
            var result = await _userFavoritesManager.AddUserFavoriteAsync(UserEntityHeader, OrgEntityHeader, favorite);
            return InvokeResult<UserFavorites>.Create(result);
        }

        /// <summary>
        /// User Service - Remove favorite
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpDelete("/api/user/favorite/{id}")]
        public async Task<InvokeResult<UserFavorites>> RemoveUserFavorite(string id)
        {
            var result = await _userFavoritesManager.RemoveUserFavoriteAsync(UserEntityHeader, OrgEntityHeader, id);
            return InvokeResult<UserFavorites>.Create(result);
        }

        /// <summary>
        /// User Services - Remove External Login by Extenral Login Id
        /// </summary>
        /// <param name="id">id of external login</param>
        /// <returns></returns>
        [HttpDelete("/api/user/externallogin/{id}")]
        public Task<InvokeResult<AppUser>> RemoveExternalLogin(string id)
        {
            return _appUserManager.RemoveExternalLoginAsync(UserEntityHeader.Id, id, UserEntityHeader);
        }

        [HttpGet("/api/user/inbox")]
        public Task<ListResponse<InboxItem>> GetUserInbox()
        {
            return _appUserInboxManager.GetAllInboxItemsAsync(OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }


        [HttpGet("/api/user/inbox/unread")]
        public Task<InvokeResult<int>> GetUserInboxCount()
        {
            return _appUserInboxManager.GetAllInboxItemCountAsync(OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/user/inbox/{partitionkey}/{rowkey}/viewed")]
        public Task<InvokeResult> MarkedAsViewed(string partitionkey, string rowkey)
        {
            return _appUserInboxManager.MarkAsReadAsync(partitionkey, rowkey, OrgEntityHeader, UserEntityHeader);
        }


        [HttpDelete("/api/user/inbox/{partitionkey}/{rowkey}")]
        public Task<InvokeResult> DeleteInboxItem(string partitionkey, string rowkey)
        {
            return _appUserInboxManager.DeleteItemAsync(partitionkey, rowkey, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Register a new user (sign-up)
        /// </summary>
        /// <param name="newUser"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("/api/user/register")]
        public async Task<InvokeResult<CreateUserResponse>> CreateNewAsync([FromBody] RegisterUser newUser)
        {
            if(String.IsNullOrEmpty(newUser.InviteId))
                newUser.InviteId = Request.Cookies["inviteid"];

            if (!EntityHeader.IsNullOrEmpty(newUser.EndUserAppOrg))
            {
                newUser.OrgId = newUser.EndUserAppOrg.Id;
            }

            var response = await _userRegistrationManager.CreateUserAsync(newUser);

             if (response.Successful && newUser.LoginType == LoginTypes.AppEndUser)
            {
                var appuser = response.Result.AppUser;

                var createCustomerRequest = CreateCustomerRequest.FromRegisterUser(newUser);
                createCustomerRequest.CreatedByUser = appuser.ToEntityHeader();

                var customerResponse = await _customerManager.CreateCustomer(createCustomerRequest);

                var customer = customerResponse.Result.ToEntityHeader();
                var contact = customerResponse.Result.PrimaryContact;
                var appUser = await _appUserManager.UpdateAppUserCompanyContactAsync(appuser.Id, customer, contact, true, appuser.CurrentOrganization.ToEntityHeader(), appuser.ToEntityHeader());
                if (appUser.Successful)
                {
                    await _signInManager.SignInAsync(appUser.Result, true);
                    response.Result.AppUser = appUser.Result;
                }
                else
                    return InvokeResult<CreateUserResponse>.FromInvokeResult(appUser.ToInvokeResult());
           }

            return response;
        }

        [HttpGet("/api/user/{id}/ssn")]
        public Task<InvokeResult<string>> GetSSNForUserAsync(string id)
        {
            return _appUserManager.GetUserSSNAsync(id, OrgEntityHeader, UserEntityHeader);
        }


        [FinanceAdmin]
        [HttpGet("/api/user/{id}/paymentaccounts")]
        public Task<InvokeResult<PaymentAccounts>> GetPaymentAccounts(string id)
        {
            return _appUserManager.GetPaymentAccountsAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [FinanceAdmin]
        [HttpPost("/api/user/{id}/paymentaccounts")]
        public Task<InvokeResult> UpdatePaymentAccounts(string id, [FromBody] PaymentAccounts paymentAccount)
        {
            return _appUserManager.UpdatePaymentAccountsAsync(id, paymentAccount, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// User Service - Register a new user by existing user (not sign up)
        /// </summary>
        /// <param name="newUser"></param>
        /// <returns></returns>
        [OrgAdmin]
        [HttpPost("/api/user/create")]
        public async Task<InvokeResult<UserInfoSummary>> CreateAuthorizedNewAsync([FromBody] RegisterUser newUser)
        {
            var result = await _userRegistrationManager.CreateUserAsync(newUser, false);
            if (!result.Successful) return InvokeResult<UserInfoSummary>.FromInvokeResult(result.ToInvokeResult());
            var setAuthResult = await _appUserManager.SetApprovedAsync(result.Result.User.Id, OrgEntityHeader, UserEntityHeader);
            if (!setAuthResult.Successful) return InvokeResult<UserInfoSummary>.FromInvokeResult(setAuthResult.ToInvokeResult());
            var addOrgResult = await _orgManager.AddUserToOrgAsync(OrgEntityHeader.Id, result.Result.User.Id, OrgEntityHeader, UserEntityHeader);
            if (!setAuthResult.Successful) return InvokeResult<UserInfoSummary>.FromInvokeResult(addOrgResult.ToInvokeResult());
            var appUser = await _appUserManager.GetUserByIdAsync(result.Result.User.Id, OrgEntityHeader, UserEntityHeader);
            return InvokeResult<UserInfoSummary>.Create(appUser.CreateSummary(false, false));
		}

        /// <summary>
        /// User Service - Register User by existing User Factory
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
		[HttpGet("/api/user/factory")]
		public  DetailResponse<RegisterViewModel> CreateRegisterFactory()
		{
			return DetailResponse<RegisterViewModel>.Create();
		}

        [HttpGet("/api/address/factory")]
        public DetailResponse<Address> CreateAddress()
        {
            return DetailResponse<Address>.Create();
        }

        /// <summary>
        /// User Service - Disable user account
        /// </summary>
        /// <param name="userid"></param>
        /// <returns></returns>
        [OrgAdmin]
        [HttpGet("/api/user/{userid}/disable")]
        public Task<InvokeResult> DisableUserAccount(string userid)
        {
            return _appUserManager.DisableAccountAsync(userid, OrgEntityHeader, UserEntityHeader);
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


        /// <summary>
        /// User Service - Get Devices Users by Repo Id
        /// </summary>
        /// <param name="repoid"></param>
        /// <returns></returns>
        [OrgAdmin]
        [HttpGet("/api/users/repo/{repoid}")]
        public Task<ListResponse<UserInfoSummary>> GetDeviceUsers(string repoid)
        {
            return _appUserManager.GetDeviceUsersAsync(repoid, OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        /// <returns></returns>
        [HttpPost("/api/user/profile/picture/upload")]
        public async Task<InvokeResult<ImageDetails>> UploadMediaAsync(IFormFile file)
        {
            using (var strm = file.OpenReadStream())
            { 
                return await _mediaServicesManager.AddImageAsPngAsync(strm, "profilepics", true, 255, 255);
            }
        }

        [OrgAdmin]
        [HttpPut("/api/user/profile/{id}/picture")]
        public Task<InvokeResult> SetProfileImage([FromBody] ImageDetails profilePicture, string id)
        {
            return _appUserManager.SetProfileImageAsync(id, profilePicture, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPut("/api/user/profile/picture")]
        public  Task<InvokeResult> SetProfileImage([FromBody] ImageDetails profilePicture)
        {
            return _appUserManager.SetProfileImageAsync(UserEntityHeader.Id, profilePicture, OrgEntityHeader, UserEntityHeader);
        }

        public class SvgElement
        {
            public string Svg;
        }

        [HttpPost("/api/user/svg/signature")]
        public Task<InvokeResult> AddSignature([FromBody] SvgElement element)
        {
            return _appUserManager.AddUserSvgSignatureAsync(element.Svg, UserEntityHeader);
        }


        [HttpPost("/api/user/svg/initials")]
        public Task<InvokeResult> AddInitials([FromBody] SvgElement element)
        {
            return _appUserManager.AddUserSvgInitialsAsync(element.Svg, UserEntityHeader);
        }

        [HttpGet("/api/user/svg/signature")]
        public Task<InvokeResult<string>> GetSignature()
        {
            return _appUserManager.GetUserSvgSignatureAsync(UserEntityHeader);
        }

        [HttpGet("/api/user/svg/initials")]
        public Task<InvokeResult<string>> GetInitials()
        {
            return _appUserManager.GetUserSvgInitialsAsync(UserEntityHeader);
        }

        [HttpDelete("/api/user/svg/signature")]
        public Task<InvokeResult> RemoveSignature()
        {
            return _appUserManager.ClearUserSvgSignatureAsync(UserEntityHeader);
        }


        [HttpDelete("/api/user/svg/initials")]
        public Task<InvokeResult> RemoveInitials()
        {
            return _appUserManager.ClearUserSvgInitialsAsync(UserEntityHeader);
        }


        [HttpGet("/api/user/svg/signature/b64png")]
        public Task<InvokeResult<string>> GetSignatureB64Png()
        {
            return _appUserManager.GetUserSvgSignatureAsB64PngAsync(UserEntityHeader);
        }

        [HttpGet("/api/user/svg/initials/b64png")]
        public Task<InvokeResult<string>> GetInitialsB64Png()
        {
            return _appUserManager.GetUserSvgInitialsAsB64PngAsync(UserEntityHeader);
        }
    }
}