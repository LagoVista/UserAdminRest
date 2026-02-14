// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: a6d30ef04370278fe81723fb8ca6d1720e35bed2528d5635b145b2fe9aae6f81
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.IoT.Web.Common.Controllers;
using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.Core.Authentication.Models;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.UserAdmin.Interfaces.Repos.Security;
using LagoVista.Core.Validation;
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.UserAdmin.Managers;
using LagoVista.AspNetCore.Identity.Managers;
using LagoVista.Core.Interfaces;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.IoT.Deployment.Admin;
using Prometheus;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.UserAdmin.Models.Security;
using System.Linq;
using LagoVista.Core.Models;
using LagoVista.ProjectManagement.Core;
using LagoVista.ProjectManagement;
using LagoVista.UserAdmin.Interfaces;
using LagoVista.UserAdmin.Interfaces.Repos.Users;
using LagoVista.UserAdmin.Interfaces.Repos.Orgs;
using System.Diagnostics;
using Microsoft.Azure.Cosmos.Serialization.HybridRow;
using Microsoft.VisualStudio.Services.Aad;
using Org.BouncyCastle.Ocsp;
using ReverseMarkdown.Converters;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace LagoVista.UserAdmin.Rest
{


    /// <summary>
    /// Authentication Services
    /// </summary>
    [AllowAnonymous]
    public class PublicAuthServices : LagoVistaBaseController
    {
        public class LoginModel
        {
            public string EndUserAppOrgId { get; set; }
            public string Module { get; set; }
            public string Email { get; set; }
            public string InviteId { get; set; }
            public string Password { get; set; }
            public bool RememberMe { get; set; }
        
            public AuthLoginRequest GetAuthRequest()
            {
                return new AuthLoginRequest()
                {
                    EndUserAppOrgId = EndUserAppOrgId,
                    InviteId = InviteId,
                    Email = Email,
                    Password = Password,
                    RememberMe = RememberMe,
                };
            }
        }

        private readonly UserManager<AppUser> _userManager;
        private readonly IAuthTokenManager _tokenManager;
        private readonly IPasswordManager _passwordManager;
        private readonly ISignInManager _signInManager;
		private readonly IClientAppManager _clientAppManager;
        private readonly IOrganizationManager _organizationManager;
        private readonly IAuthenticationLogManager _authenticationLogManager;
        private readonly IMileStoneRepo _mileStoneRepo;
        private readonly IProjectRepo _projectRepo;
        private readonly IAppUserRepo _appUserRepo;
        private readonly IOrgUserRepo _orgUserRepo;
        private readonly IIUserAccessManager _userAccessManager;
        private readonly IDeploymentInstanceManager _instanceManager;
        private readonly IToDoRepo _todoRepo;

        protected static readonly Counter UserLogin = Metrics.CreateCounter("nuviot_login", "successful user login.", "source");
        protected static readonly Counter UserLoginFailed = Metrics.CreateCounter("nuviot_login_failed", "unsuccessful user login.", "source", "reason");

        public PublicAuthServices(IAuthTokenManager tokenManager, IPasswordManager passwordManager, IAdminLogger logger, IAppUserManager appUserManager, IMileStoneRepo mileStoneRepo, IProjectRepo projectRepo, IOrganizationManager orgManager, UserManager<AppUser> userManager, IToDoRepo todoRepo,
            IAuthenticationLogManager authenticationLogManager, IAppUserRepo appUserRepo, IOrgUserRepo orgUserRepo, IDeploymentInstanceManager instanceManager, IIUserAccessManager userAccessManager, ISignInManager signInManager, IEmailSender emailSender, IAppConfig appConfig, IClientAppManager clientAppManager) : base(userManager, logger)
        {
            _userManager = userManager;
            _tokenManager = tokenManager;
            _passwordManager = passwordManager;
            _signInManager = signInManager;
			_clientAppManager = clientAppManager;
            _organizationManager = orgManager;
            _authenticationLogManager = authenticationLogManager;
            _mileStoneRepo = mileStoneRepo;
            _projectRepo = projectRepo;
            _userAccessManager = userAccessManager;
            _appUserRepo = appUserRepo;
            _orgUserRepo = orgUserRepo ?? throw new ArgumentNullException(nameof(orgUserRepo));
            _instanceManager = instanceManager ?? throw new ArgumentNullException(nameof(instanceManager)); ;
            _todoRepo = todoRepo ?? throw new ArgumentNullException(nameof(todoRepo));
        }

        private Task<InvokeResult<AuthResponse>> HandleAuthRequest(AuthRequest req)
        {
            if (req.GrantType == AuthTokenManager.GRANT_TYPE_PASSWORD)
            {
                return _tokenManager.AccessTokenGrantAsync(req);
            }
            else if (req.GrantType == AuthTokenManager.GRANT_TYPE_REFRESHTOKEN)
            {
                return _tokenManager.RefreshTokenGrantAsync(req);
            }
            else if(req.GrantType == AuthTokenManager.GRANT_TYPE_SINGLEUSETOKEN)
            {
                return _tokenManager.SingleUseTokenGrantAsync(req);
            }
            else if(String.IsNullOrEmpty(req.GrantType))
            {
                throw new Exception($"Missing Grant Type.");
            }
            else
            {
                throw new Exception($"Invalid Grant Type - [{req.GrantType}]");
            }
        }

        /// <summary>
        /// Auth by JSON Body
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/auth/login")]
        [HttpPost("/api/v1/auth")]
        [AllowAnonymous]
        public async Task<InvokeResult<AuthResponse>> AuthFromBody([FromBody] AuthRequest req)
        {
            req.InviteId = Request.Cookies["inviteid"];
            Response.Cookies.Delete("inviteid");

            var result = await HandleAuthRequest(req);
            if(result.Successful)
                UserLogin.WithLabels("auth-request").Inc();
            else
                UserLoginFailed.WithLabels("auth-request","failed").Inc();

            return result;
        }

        /// <summary>
        /// Auth by JSON Body
        /// </summary>
        /// <param name="req"></param>
        /// <param name="repoId"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth/repo/{repoid}")]
        [AllowAnonymous]
        public async Task<InvokeResult<AuthResponse>> AuthFromBody(String repoId, [FromBody] AuthRequest req)
        {
            req.Email = $"{repoId}-{req.Email}";

            var result = await HandleAuthRequest(req);
            if (result.Successful)
                UserLogin.WithLabels("auth-request-repo").Inc();
            else
                UserLoginFailed.WithLabels("auth-request-repo", "failed").Inc();

            return result;
        }

        /// <summary>
        /// Auth by Form POST
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/auth/form")]
        [AllowAnonymous]
        public async Task<InvokeResult<AuthResponse>> AuthFromForm([FromForm] AuthRequest req)
        {
            var result = await HandleAuthRequest(req);
            if (result.Successful)
                UserLogin.WithLabels("auth-request-form").Inc();
            else
                UserLoginFailed.WithLabels("auth-request-form", "failed").Inc();

            return result;
        }

        /// <summary>
        /// Auth by Form Post with Simple Email Address and Password, will set cookie rather than JWT
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("/api/auth/v1/login")]
        [HttpPost("/api/v1/login")]
        public async Task<InvokeResult<UserLoginResponse>> CookieAuthFromForm([FromBody] LoginModel model)
        {
            model.InviteId = Request.Cookies["inviteid"];
            Response.Cookies.Delete("inviteid");

            var result = await _signInManager.PasswordSignInAsync(model.GetAuthRequest());

            if (result.Successful)
                UserLogin.WithLabels("cookie-auth-request-repo").Inc();
            else
                UserLoginFailed.WithLabels("cookie-auth-request-repo", "failed").Inc();
            return result;
        }

        /// <summary>
        /// Auth by Form Post with Simple Email Address and Password, will set cookie rather than JWT
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("/api/v2/login")]
        public async Task<InvokeResult<PortalPageData>> CookieAuthFromFormV2([FromBody] LoginModel model)
        {            
            var result = await _signInManager.PasswordSignInAsync(model.GetAuthRequest());
            Console.WriteLine("resource=>" + result.Successful.ToString());

            if (result.Successful)
                UserLogin.WithLabels("cookie-auth-request-repo").Inc();
            else
                UserLoginFailed.WithLabels("cookie-auth-request-repo", "failed").Inc();

            if (!result.Successful)
            {
                return InvokeResult<PortalPageData>.FromInvokeResult(result.ToInvokeResult());
            }            

            var data = new PortalPageData(result.Result);
            var orgUsers = await _orgUserRepo.GetUsersForOrgAsync(result.Result.User.CurrentOrganization.Id);
            data.AddMetric("Load Org Users");
            var activeUsers = (await _appUserRepo.GetUserSummaryForListAsync(orgUsers, true)).Where(usr => !usr.IsAccountDisabled && !usr.IsRuntimeUser && !usr.IsUserDevice).OrderBy(usr => usr.Name);
            data.ActiveUsers = activeUsers.Select(au => EntityHeader.Create(au.Id, au.Name)).ToList();
            data.AddMetric("Load Active Users");

            var currentOrgId = result.Result.User.CurrentOrganization.Id;
            var orgEh = result.Result.User.CurrentOrganization.ToEntityHeader();
            var userEh = result.Result.User.ToEntityHeader();
            
            var mileStones = await _mileStoneRepo.GetActiveMileStonesAsync(currentOrgId, ListRequest.CreateForAll());
            data.Milestones = mileStones.Model.ToList();
            data.AddMetric("Load Milestones");
            data.ToDos = (await _todoRepo.GetOpenToDosAssignedToAsync(userEh.Id, ListRequest.CreateForAll())).Model.ToList();
            data.AddMetric("Load ToDos");
            var projects = await _projectRepo.GetActiveProjectAsync(currentOrgId, ListRequest.CreateForAll());
            data.ActiveProjects = projects.Model.Select(prj => EntityHeader.Create(prj.Id, prj.Key, prj.Name)).ToList();
            data.AddMetric("Load Active Projects");


            var wsREsult = await _instanceManager.GetRemoteMonitoringURIAsync("ToDo", userEh.Id, "normal", orgEh, userEh);
            data.ToDoWebSocketUrl = wsREsult.Result;
            data.AddMetric($"Loaded ToDo Web Socket URL");

            wsREsult = await _instanceManager.GetRemoteMonitoringURIAsync("Inbox", userEh.Id, "normal", orgEh, userEh);
            data.AddMetric($"Loaded In box Socket URL");
            data.InboxWebSocketUrl = wsREsult.Result;

            data.ServerLoadTime = (data.Metrics.Sum(met => met.Ms) / 1000.0);

            return InvokeResult<PortalPageData>.Create(data);
         }

        /// <summary>
        /// Auth by Form Post with Simple Email Address and Password, will set cookie rather than JWT
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("/api/v1/loginkiosk")]
        public async Task<InvokeResult<string>> KioskCookieAuthFromForm([FromForm] LoginModel model)
        {
            if (model != null && !string.IsNullOrEmpty(model.Password))
            {
                var kioskResult = await _clientAppManager.AuthorizeAppAsync(model.Email, model.Password); /* ClientId, ApiKey */
                if (kioskResult.Successful)
                {
                    UserLogin.WithLabels("kiosk").Inc();

                    var clientApp = kioskResult.Result;
                    //              var claims = new[]
                    //              {
                    //                  new Claim(ClaimsFactory.InstanceId, clientApp.DeploymentInstance.Id),
                    //                  new Claim(ClaimsFactory.InstanceName, clientApp.DeploymentInstance.Text),
                    //                  new Claim(ClaimsFactory.CurrentOrgId, clientApp.OwnerOrganization.Id),
                    //                  new Claim(ClaimsFactory.CurrentOrgName, clientApp.OwnerOrganization.Text),
                    //new Claim(ClaimsFactory.CurrentUserId, clientApp.ClientAppUser.Id),
                    //                  new Claim(ClaimTypes.NameIdentifier, clientApp.ClientAppUser.Text),
                    //                  new Claim(ClaimTypes.Surname, "system"),
                    //new Claim(ClaimTypes.GivenName, clientApp.ClientAppUser.Text),
                    //                  new Claim(ClaimsFactory.KioskId, clientApp.Kiosk.Id),
                    //                  new Claim(ClaimsFactory.EmailVerified, true.ToString()),
                    //                  new Claim(ClaimsFactory.PhoneVerfiied, true.ToString()),
                    //                  new Claim(ClaimsFactory.IsSystemAdmin, false.ToString()),
                    //                  new Claim(ClaimsFactory.IsAppBuilder, false.ToString()),
                    //                  new Claim(ClaimsFactory.IsOrgAdmin, false.ToString()),
                    //                  new Claim(ClaimsFactory.IsPreviewUser, false.ToString()),
                    //              };

                    var currentOrg = await _organizationManager.GetOrganizationAsync(clientApp.OwnerOrganization.Id, clientApp.OwnerOrganization, clientApp.CreatedBy);
                    

      //              var identity = new ClaimsIdentity(claims);
                    var clientAppUser = new AppUser(clientApp.ClientAppUser.Id, "system")
                    {
                        Id = clientApp.ClientAppUser.Id,
                        EmailConfirmed = true,
                        PhoneNumberConfirmed = true,
                        IsAppBuilder = false,
                        IsOrgAdmin = false,
                        IsPreviewUser = false,
                        IsSystemAdmin = false,
                        IsUserDevice = false,
                        OwnerUser = clientApp.OwnerUser,
                        UserName = clientApp.ClientAppUser.Id,
						OwnerOrganization = clientApp.OwnerOrganization,
						CurrentOrganization = currentOrg.CreateSummary(),
					};

                    try
                    {
                        await _signInManager.SignInAsync(clientAppUser, false);

                        return InvokeResult<string>.Create(clientApp.Kiosk.Id);
                    }
                    catch
                    {
                        UserLoginFailed.WithLabels("kiosk", "failed").Inc();
                        return InvokeResult<string>.FromError("Could not authenticate (kiosk:1)");
                    }
                }
            }

            UserLoginFailed.WithLabels("kiosk", "failed").Inc();

            return InvokeResult<string>.FromError("Could not authenticate (kiosk:2)");
        }

        /// <summary>
        /// Auth by Form Post with Simple Email Address and Password, will set cookie rather than JWT
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/auth/v1/logoff")]
        [HttpGet("/api/v1/logoff")]
        public async Task<InvokeResult> Logoff()
        {
            
            await _signInManager.SignOutAsync();
            await _authenticationLogManager.AddAsync(AuthLogTypes.UserLogout, UserEntityHeader.Id, UserEntityHeader.Text, OrgEntityHeader.Id, OrgEntityHeader.Text);
            return InvokeResult.Success;
        }

        /// <summary>
        /// User Service - Send Reset Password Link
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/auth/resetpassword/sendlink")]
        public Task<InvokeResult> SendResetPasswordLinkAsync([FromBody] SendResetPasswordLink sendResetPasswordLink)
        {
            return _passwordManager.SendResetPasswordLinkAsync(sendResetPasswordLink);
        }

        [AllowAnonymous]
        [HttpGet("/api/auth/invite/accept/{inviteid}")]
        public async Task<IActionResult> AcceptInvite(string inviteid)
        {            
            if (User.Identity.IsAuthenticated)
            {
                await _authenticationLogManager.AddAsync(AuthLogTypes.AcceptingInvite, UserEntityHeader, OrgEntityHeader, extras: "Accepting direct invite, authenticated.", inviteId: inviteid);
                var result = await _organizationManager.AcceptInvitationAsync(inviteid, UserEntityHeader.Id);
                if(result.Successful)
                {
                    var redirect = result.Result.RedirectPage;
                    await _authenticationLogManager.AddAsync(AuthLogTypes.AcceptedInvite, UserEntityHeader, OrgEntityHeader, extras: "Done accepted direct invite, authenticated - success.", redirectUri: redirect, inviteId: inviteid);
                    return Redirect(redirect);
                }
                else
                {
                    var redirect = result.RedirectURL;
                    await _authenticationLogManager.AddAsync(AuthLogTypes.AcceptedInvite, UserEntityHeader, OrgEntityHeader, extras: "Done accepted direct invite, authenticated - failed.", redirectUri: redirect, inviteId: inviteid, errors: result.ErrorMessage);
                    return Redirect(redirect);
                }
            }
            else
            {
                Response.Cookies.Append("inviteid", inviteid);
                var redirect = CommonLinks.AcceptInviteId.Replace("{inviteid}", inviteid);
                await _authenticationLogManager.AddAsync(AuthLogTypes.AcceptingInvite, userId: "?", redirectUri: redirect, extras: "Not Authenticated, Rediret to Accept Invite Page", inviteId: inviteid);
                return Redirect(redirect);
            }
        }

        /// <summary>
        /// User Service - Reset Password
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/auth/resetpassword")]
        [AllowAnonymous]
        public Task<InvokeResult> ResetPasswordAsync([FromBody] ResetPassword resetPassword)
        {
            return _passwordManager.ResetPasswordAsync(resetPassword);
        }
    }

    [Authorize]
    public class AuthServices : LagoVistaBaseController
    {
        private readonly IPasswordManager _passwordManager;
        private readonly IAuthenticationLogManager _authenticationLogManager;


        public AuthServices(IPasswordManager passwordManager, IAuthenticationLogManager authenticationLogManager, UserManager<AppUser> userManager, IAdminLogger logger) 
        : base(userManager, logger)
        {
            _passwordManager = passwordManager ?? throw new ArgumentNullException(nameof(passwordManager));
            _authenticationLogManager = authenticationLogManager ?? throw new ArgumentNullException(nameof(authenticationLogManager));
        }

        /// <summary>
        /// User Service - Change Password
        /// </summary>
        /// <returns></returns>
        [HttpPost("/api/auth/changepassword")]
        [Authorize]
        public Task<InvokeResult> ChangePasswordAsync([FromBody] ChangePassword changePassword)
        {
            return _passwordManager.ChangePasswordAsync(changePassword, OrgEntityHeader, UserEntityHeader);
        }

        [SystemAdmin]
        [HttpGet("/api/sys/auth/log")]
        [HttpGet("/sys/auth/log")]
        public Task<ListResponse<AuthenticationLog>> GetAllAuthAsync()
        {
            return _authenticationLogManager.GetAllAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }

        [SystemAdmin]
        [HttpGet("/api/sys/auth/log/{type}")]
        [HttpGet("/sys/auth/log/{type}")]
        public Task<ListResponse<AuthenticationLog>> GetAuthAsync(string type)
        {
            var authLogType = Enum.Parse<AuthLogTypes>(type, true);

            return _authenticationLogManager.GetAsync(authLogType, GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/auth/log/{type}")]
        [HttpGet("/auth/log/{type}")]
        [SystemAdmin]
        public Task<ListResponse<AuthenticationLog>> GetAuthAsyncForOrg(string type)
        {
            var authLogType = Enum.Parse<AuthLogTypes>(type, true);

            return _authenticationLogManager.GetAsync(OrgEntityHeader.Id, authLogType, GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/auth/log")]
        [SystemAdmin]
        public Task<ListResponse<AuthenticationLog>> GetAllAuthAsyncForOrg()
        {
            return _authenticationLogManager.GetAllAsync(OrgEntityHeader.Id, GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }


        [HttpGet("/api/user/claims")]
        [HttpGet("/user/claims")]
        public IEnumerable<String> GetClaims()
        {
            return HttpContext.User.Claims.Select(clm=>$"{clm.Type}={clm.Value}");
        }
    }
}
