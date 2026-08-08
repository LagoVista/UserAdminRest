using LagoVista.AspNetCore.Identity.Managers;
using LagoVista.Core.Authentication.Models;
using LagoVista.Core.Interfaces;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Deployment.Admin;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.ProjectManagement;
using LagoVista.ProjectManagement.Core;
using LagoVista.UserAdmin.Authentication;
using LagoVista.UserAdmin.Interfaces;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Interfaces.Repos.Orgs;
using LagoVista.UserAdmin.Interfaces.Repos.Security;
using LagoVista.UserAdmin.Interfaces.Repos.Users;
using LagoVista.UserAdmin.Managers;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.UserAdmin.Models.Security;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Prometheus;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
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
                return new AuthLoginRequest
                {
                    EndUserAppOrgId = EndUserAppOrgId,
                    InviteId = InviteId,
                    Email = Email,
                    Password = Password,
                    RememberMe = RememberMe
                };
            }
        }

        private readonly UserManager<AppUser> _userManager;
        private readonly IAuthTokenManager _tokenManager;
        private readonly IPasswordManager _passwordManager;
        private readonly ISignInManager _signInManager;
        private readonly IClientAppManager _clientAppManager;
        private readonly IOrganizationManager _organizationManager;
        private readonly IAuthenticationFlowService _authenticationFlowService;
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
            IAuthenticationLogManager authenticationLogManager, IAppUserRepo appUserRepo, IOrgUserRepo orgUserRepo, IDeploymentInstanceManager instanceManager, IIUserAccessManager userAccessManager, ISignInManager signInManager, IEmailSender emailSender, IAppConfig appConfig, IClientAppManager clientAppManager, IAuthenticationFlowService authenticationFlowService) : base(userManager, logger)
        {
            _userManager = userManager;
            _tokenManager = tokenManager;
            _passwordManager = passwordManager;
            _signInManager = signInManager;
            _clientAppManager = clientAppManager;
            _organizationManager = orgManager;
            _authenticationFlowService = authenticationFlowService ?? throw new ArgumentNullException(nameof(authenticationFlowService));
            _authenticationLogManager = authenticationLogManager;
            _mileStoneRepo = mileStoneRepo;
            _projectRepo = projectRepo;
            _userAccessManager = userAccessManager;
            _appUserRepo = appUserRepo;
            _orgUserRepo = orgUserRepo ?? throw new ArgumentNullException(nameof(orgUserRepo));
            _instanceManager = instanceManager ?? throw new ArgumentNullException(nameof(instanceManager));
            _todoRepo = todoRepo ?? throw new ArgumentNullException(nameof(todoRepo));
        }

        private Task<InvokeResult<AuthResponse>> HandleAuthRequest(AuthRequest req)
        {
            if (req.GrantType == AuthTokenManager.GRANT_TYPE_PASSWORD)
                return _tokenManager.AccessTokenGrantAsync(req);

            if (req.GrantType == AuthTokenManager.GRANT_TYPE_REFRESHTOKEN)
                return _tokenManager.RefreshTokenGrantAsync(req);

            if (req.GrantType == AuthTokenManager.GRANT_TYPE_SINGLEUSETOKEN)
                return _tokenManager.SingleUseTokenGrantAsync(req);

            if (String.IsNullOrEmpty(req.GrantType))
                throw new Exception("Missing Grant Type.");

            throw new Exception($"Invalid Grant Type - [{req.GrantType}]");
        }

        [HttpPost("/api/auth/login")]
        [HttpPost("/api/v1/auth")]
        [AllowAnonymous]
        public async Task<InvokeResult<AuthResponse>> AuthFromBody([FromBody] AuthRequest req)
        {
            req.InviteId = Request.Cookies["inviteid"];
            Response.Cookies.Delete("inviteid");

            var result = await HandleAuthRequest(req);
            if (result.Successful)
                UserLogin.WithLabels("auth-request").Inc();
            else
                UserLoginFailed.WithLabels("auth-request", "failed").Inc();

            return result;
        }

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

        [HttpPost("/api/auth/v1/login")]
        [HttpPost("/api/v1/login")]
        public async Task<InvokeResult<AuthenticationResponse>> CookieAuthFromForm([FromBody] LoginModel model)
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

        [HttpPost("/api/v2/login")]
        public Task<InvokeResult<AuthenticationResponse>> CookieAuthFromFormV2([FromBody] LoginModel model)
        {
            return CookieAuthFromForm(model);
        }

        [HttpPost("/api/v1/loginkiosk")]
        public async Task<InvokeResult<string>> KioskCookieAuthFromForm([FromForm] LoginModel model)
        {
            if (model != null && !string.IsNullOrEmpty(model.Password))
            {
                var kioskResult = await _clientAppManager.AuthorizeAppAsync(model.Email, model.Password);
                if (kioskResult.Successful)
                {
                    UserLogin.WithLabels("kiosk").Inc();

                    var clientApp = kioskResult.Result;
                    var currentOrg = await _organizationManager.GetOrganizationAsync(clientApp.OwnerOrganization.Id, clientApp.OwnerOrganization, clientApp.CreatedBy);
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
                        CurrentOrganization = currentOrg.CreateSummary()
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

        [HttpGet("/api/auth/v1/logoff")]
        [HttpGet("/api/v1/logoff")]
        public async Task<InvokeResult> Logoff()
        {
            await _signInManager.SignOutAsync();
            await _authenticationLogManager.AddAsync(AuthLogTypes.UserLogout, UserEntityHeader.Id, UserEntityHeader.Text, OrgEntityHeader.Id, OrgEntityHeader.Text);
            return InvokeResult.Success;
        }

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
                await _authenticationLogManager.AddAsync(AuthLogTypes.InviteAcceptanceStarted, UserEntityHeader, OrgEntityHeader, extras: "Accepting direct invite, authenticated.", inviteId: inviteid);
                var result = await _organizationManager.AcceptInvitationAsync(inviteid, UserEntityHeader.Id);
                if (result.Successful)
                {
                    var redirect = result.Result.RedirectPage;
                    await _authenticationLogManager.AddAsync(AuthLogTypes.InviteAcceptanceSucceeded, UserEntityHeader, OrgEntityHeader, extras: "Done accepted direct invite, authenticated - success.", redirectUri: redirect, inviteId: inviteid);
                    return Redirect(redirect);
                }

                var failedRedirect = result.RedirectURL;
                await _authenticationLogManager.AddAsync(AuthLogTypes.InviteAcceptanceFailed, UserEntityHeader, OrgEntityHeader, extras: "Done accepted direct invite, authenticated - failed.", redirectUri: failedRedirect, inviteId: inviteid, errors: result.ErrorMessage);
                return Redirect(failedRedirect);
            }

            Response.Cookies.Append("inviteid", inviteid);
            var redirectPage = CommonLinks.AcceptInviteId.Replace("{inviteid}", inviteid);
            await _authenticationLogManager.AddAsync(AuthLogTypes.InviteAcceptanceFailed, userId: "?", redirectUri: redirectPage, extras: "Not Authenticated, Redirect to Accept Invite Page", inviteId: inviteid);
            return Redirect(redirectPage);
        }

        [HttpPost("/api/auth/resetpassword/verifycode")]
        [AllowAnonymous]
        public Task<InvokeResult<string>> VerifyPasswordRecoveryCodeAsync([FromBody] VerifyPasswordResetCode request)
        {
            return _authenticationFlowService.VerifyPasswordRecoveryAsync(request);
        }

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
        private readonly IAuthenticationFlowService _authenticationFlowService;
        private readonly IAuthenticationLogManager _authenticationLogManager;

        public AuthServices(IPasswordManager passwordManager, IAuthenticationFlowService authenticationFlowService, IAuthenticationLogManager authenticationLogManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _passwordManager = passwordManager ?? throw new ArgumentNullException(nameof(passwordManager));
            _authenticationFlowService = authenticationFlowService ?? throw new ArgumentNullException(nameof(authenticationFlowService));
            _authenticationLogManager = authenticationLogManager ?? throw new ArgumentNullException(nameof(authenticationLogManager));
        }

        [HttpPost("/api/auth/changepassword")]
        [Authorize]
        public Task<InvokeResult> ChangePasswordAsync([FromBody] ChangePassword changePassword)
        {
            return _authenticationFlowService.ChangePasswordAsync(changePassword, OrgEntityHeader, UserEntityHeader);
        }

        [OrgAdmin]
        [Authorize]
        [HttpPost("/api/auth/setuserpassword")]
        public Task<InvokeResult> SetUserPassword([FromBody] ChangePassword changePassword)
        {
            return _passwordManager.SetUserPasswordAsync(changePassword, OrgEntityHeader, UserEntityHeader);
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
            return HttpContext.User.Claims.Select(clm => $"{clm.Type}={clm.Value}");
        }
    }
}