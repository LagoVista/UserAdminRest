using LagoVista.AspNetCore.Identity.Interfaces;
using LagoVista.Core.Validation;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [ApiController]
    [AllowAnonymous]
    public class ContinuitySessionController : ControllerBase
    {
        private const string ContinuityCookieName = "aptix_continuity";

        private readonly IContinuitySessionManager _continuitySessionManager;

        public ContinuitySessionController(IContinuitySessionManager continuitySessionManager)
        {
            _continuitySessionManager = continuitySessionManager ?? throw new ArgumentNullException(nameof(continuitySessionManager));
        }

        [HttpPost("/api/continuity/session")]
        public async Task<InvokeResult<ContinuitySessionView>> ResolveAsync()
        {
            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";

            Request.Cookies.TryGetValue(ContinuityCookieName, out var continuityToken);
            var result = await _continuitySessionManager.ResolveAsync(continuityToken);
            if (!result.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(result.ToInvokeResult());
            if (result.Result == null || String.IsNullOrWhiteSpace(result.Result.ContinuityToken)) return InvokeResult<ContinuitySessionView>.FromError("Could not establish the continuity session.");

            Response.Cookies.Append(ContinuityCookieName, result.Result.ContinuityToken, CreateCookieOptions(result.Result.IdentityExpiresUtc));
            return InvokeResult<ContinuitySessionView>.Create(ContinuitySessionView.FromSession(result.Result));
        }

        private static CookieOptions CreateCookieOptions(DateTime expiresUtc)
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                IsEssential = true,
                Path = "/",
                Expires = new DateTimeOffset(DateTime.SpecifyKind(expiresUtc, DateTimeKind.Utc))
            };
        }
    }

    public class ContinuitySessionView
    {
        public string ActorId { get; set; }
        public string IdentityStage { get; set; }
        public string AccessToken { get; set; }
        public DateTime AccessTokenExpiresUtc { get; set; }
        public DateTime IdentityExpiresUtc { get; set; }
        public bool WasRestored { get; set; }
        public string ProvisionalEnvironmentId { get; set; }
        public string AppUserId { get; set; }
        public string OrganizationId { get; set; }
        public string SubscriptionId { get; set; }
        public string BootstrapContext { get; set; }

        public static ContinuitySessionView FromSession(ContinuitySessionResponse session)
        {
            if (session == null) throw new ArgumentNullException(nameof(session));

            return new ContinuitySessionView
            {
                ActorId = session.ActorId,
                IdentityStage = session.IdentityStage,
                AccessToken = session.AccessToken,
                AccessTokenExpiresUtc = session.AccessTokenExpiresUtc,
                IdentityExpiresUtc = session.IdentityExpiresUtc,
                WasRestored = session.WasRestored,
                ProvisionalEnvironmentId = session.ProvisionalEnvironmentId,
                AppUserId = session.AppUserId,
                OrganizationId = session.OrganizationId,
                SubscriptionId = session.SubscriptionId,
                BootstrapContext = session.BootstrapContext
            };
        }
    }
}
