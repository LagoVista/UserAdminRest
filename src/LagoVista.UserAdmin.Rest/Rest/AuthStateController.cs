using LagoVista.AspNetCore.Identity.Managers;
using LagoVista.Core;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{

    public class AuthSessionSnapshot
    {
        public bool A { get; set; }   // authenticated
        public bool R { get; set; }   // registered
        public bool E { get; set; }   // email verified (or “confirmed”)
        public bool O { get; set; }   // has current org
        public bool M { get; set; }   // step-up satisfied
        public bool EmailVerificationPending { get; set; } // hard-stop gate
        public bool ProfileComplete { get; set; }          // required fields present (name/email)
        public string NextPath { get; set; } // null unless server wants client to navigate
    }


    public class AuthStateService : LagoVistaBaseController
    {
        private readonly IAdminLogger _logger;

        private readonly IEntryIntentService _entryIntentService;
        private readonly IHttpContextAccessor _http;

        public AuthStateService(
            UserManager<AppUser> userManager,
            IAdminLogger logger,
            IEntryIntentService entryIntentService,
            IHttpContextAccessor http) : base(userManager, logger)
        {
            _entryIntentService = entryIntentService;
            _http = http;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        [AllowAnonymous]
        [HttpGet("/api/auth/session")]
        public async Task<AuthSessionSnapshot> GetAuthSession()
        {

            var authState = new AuthSessionSnapshot
            {
                A = User.Identity.IsAuthenticated,
                E = User.HasClaim(ClaimsFactory.EmailVerified, true.ToString()),
                O = User.Claims.Any(clm => clm.Type == ClaimsFactory.CurrentOrgId) && User.Claims.First(clm => clm.Type == ClaimsFactory.CurrentOrgId).Value != "-" ,
            };

            var mfaTimeStamp = User.Claims.FirstOrDefault(clm => clm.Type == ClaimsFactory.MfaStepUpTimeStamp);
            if (mfaTimeStamp != null)
            {
                var timeStamp = mfaTimeStamp.Value.ToDateTime();
                if (DateTime.UtcNow.Subtract(timeStamp).TotalMinutes < 15)
                {
                    authState.M = true;
                }
            }

            var verifyClaimTimeStamp = User.Claims.FirstOrDefault(clm => clm.Type == ClaimsFactory.VerifyEmailSentTimeStamp);
            if (verifyClaimTimeStamp != null)
            {
                var timeStamp = verifyClaimTimeStamp.Value.ToDateTime();
                if (DateTime.UtcNow.Subtract(timeStamp).TotalMinutes < 30)
                {
                    authState.EmailVerificationPending = true;
                }
            }

            if (User.Claims.Any(clm => clm.Type == ClaimTypes.Email) && User.Claims.First(clm => clm.Type == ClaimTypes.Email).Value != "-" &&
                User.Claims.Any(clm => clm.Type == ClaimTypes.Surname) && User.Claims.First(clm => clm.Type == ClaimTypes.Surname).Value != "-" &&
                User.Claims.Any(clm => clm.Type == ClaimTypes.GivenName) && User.Claims.First(clm => clm.Type == ClaimTypes.GivenName).Value != "-")
            {
                authState.R = true;
                authState.ProfileComplete = true;
            }

            if (!authState.A)
                authState.NextPath = "/auth";
            else if (!authState.ProfileComplete)
                authState.NextPath = "/auth/user/register";
            else if (!authState.E)
                authState.NextPath = "/auth/verify-email";
            else if (!authState.O)
                authState.NextPath = "/auth/org/create";
            else
            {
                // super fast cookie check first (no Redis hit if absent)
                var ctx = _http.HttpContext;
                if (ctx != null && ctx.Request.Cookies.ContainsKey(EntryIntentConstants.CookieName))
                {
                    var intent = await _entryIntentService.ConsumeAsync();
                    if (intent != null && !string.IsNullOrWhiteSpace(intent.Path))
                    {
                        // optional: loop prevention (don’t send them back into auth funnel)
                        if (!intent.Path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase) &&
                            !intent.Path.Equals("/api/auth/session", StringComparison.OrdinalIgnoreCase))
                        {
                            authState.NextPath = intent.Path;
                        }
                    }
                }
            }

            _logger.Trace($"{this.Tag()} - Current Status", authState.A.ToString().ToKVP("authenticated"), 
                                                        authState.R.ToString().ToKVP("registered"),
                                                        authState.E.ToString().ToKVP("emailVerified"),
                                                        authState.O.ToString().ToKVP("hasOrg"),
                                                        authState.M.ToString().ToKVP("mfaSatisfied"),
                                                        authState.EmailVerificationPending.ToString().ToKVP("emailVerificationPending"),
                                                        authState.ProfileComplete.ToString().ToKVP("profileComplete"),
                                                        authState.NextPath.ToKVP("nextPath"));

            return authState;
        }
    }
}