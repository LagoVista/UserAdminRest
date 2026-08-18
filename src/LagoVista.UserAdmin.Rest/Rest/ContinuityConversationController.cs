using LagoVista.AspNetCore.Identity.Authorization;
using LagoVista.AspNetCore.Identity.Interfaces;
using LagoVista.AspNetCore.Identity.Managers;
using LagoVista.Core.Validation;
using LagoVista.UserAdmin;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [ApiController]
    [Authorize(AuthenticationSchemes = "Bearer,Identity.Application")]
    public class ContinuityConversationController : ControllerBase
    {
        private const string ContinuityCookieName = "aptix_continuity";

        private readonly IContinuityConversationManager _conversationManager;
        private readonly IContinuitySessionManager _continuitySessionManager;
        private readonly IAnonymousVisitorPromotionManager _promotionManager;
        private readonly IAnonymousVisitorPromotionOptions _promotionOptions;
        private readonly IProvisionalEnvironmentManager _provisionalEnvironmentManager;

        public ContinuityConversationController(IContinuityConversationManager conversationManager, IContinuitySessionManager continuitySessionManager, IAnonymousVisitorPromotionManager promotionManager, IAnonymousVisitorPromotionOptions promotionOptions, IProvisionalEnvironmentManager provisionalEnvironmentManager)
        {
            _conversationManager = conversationManager ?? throw new ArgumentNullException(nameof(conversationManager));
            _continuitySessionManager = continuitySessionManager ?? throw new ArgumentNullException(nameof(continuitySessionManager));
            _promotionManager = promotionManager ?? throw new ArgumentNullException(nameof(promotionManager));
            _promotionOptions = promotionOptions ?? throw new ArgumentNullException(nameof(promotionOptions));
            _provisionalEnvironmentManager = provisionalEnvironmentManager ?? throw new ArgumentNullException(nameof(provisionalEnvironmentManager));
        }

        [AllowAnonymousVisitor]
        [AllowProvisionalIdentity]
        [HttpGet("/api/continuity/conversation")]
        public async Task<InvokeResult<ContinuityConversationResponse>> GetConversationAsync()
        {
            SetNoStore();
            var identityResult = await GetContinuityIdentityAsync();
            if (!identityResult.Successful) return InvokeResult<ContinuityConversationResponse>.FromInvokeResult(identityResult.ToInvokeResult());
            return await _conversationManager.GetAsync(identityResult.Result.ActorId);
        }

        [AllowAnonymousVisitor]
        [AllowProvisionalIdentity]
        [HttpPost("/api/continuity/conversation/message")]
        public async Task<InvokeResult<ContinuityConversationResponse>> SendMessageAsync([FromBody] ContinuityConversationMessageRequest request)
        {
            SetNoStore();
            var identityResult = await GetContinuityIdentityAsync();
            if (!identityResult.Successful) return InvokeResult<ContinuityConversationResponse>.FromInvokeResult(identityResult.ToInvokeResult());
            return await _conversationManager.SendAsync(identityResult.Result.ActorId, identityResult.Result.IdentityStage, request);
        }

        [AllowAnonymousVisitor]
        [HttpGet("/api/continuity/promotion")]
        public InvokeResult<ContinuityPromotionView> GetPromotionAsync()
        {
            SetNoStore();
            var identityResult = GetVisitorIdentity();
            if (!identityResult.Successful) return InvokeResult<ContinuityPromotionView>.FromInvokeResult(identityResult.ToInvokeResult());
            if (String.IsNullOrWhiteSpace(_promotionOptions.TermsAndConditionsVersion)) return InvokeResult<ContinuityPromotionView>.FromError("AnonymousVisitor:TermsAndConditionsVersion is not configured.");

            return InvokeResult<ContinuityPromotionView>.Create(new ContinuityPromotionView
            {
                TermsAndConditionsVersion = _promotionOptions.TermsAndConditionsVersion
            });
        }

        [AllowAnonymousVisitor]
        [HttpPost("/api/continuity/promotion")]
        public async Task<InvokeResult<ContinuitySessionView>> PromoteAsync([FromBody] ContinuityPromotionRequest request)
        {
            SetNoStore();
            var identityResult = GetVisitorIdentity();
            if (!identityResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(identityResult.ToInvokeResult());
            if (request == null) return InvokeResult<ContinuitySessionView>.FromError("Promotion request is required.");

            var promotionResult = await _promotionManager.PromoteAsync(identityResult.Result.ActorId, HttpContext.Connection.RemoteIpAddress?.ToString(), new AnonymousVisitorPromotionRequest
            {
                TermsAndConditionsAccepted = request.TermsAndConditionsAccepted,
                TermsAndConditionsVersion = request.TermsAndConditionsVersion
            });

            if (!promotionResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(promotionResult.ToInvokeResult());
            if (promotionResult.Result == null || String.IsNullOrWhiteSpace(promotionResult.Result.RecoveryToken)) return InvokeResult<ContinuitySessionView>.FromError("Could not establish the provisional continuity session.");

            var sessionResult = await _continuitySessionManager.ResolveAsync(promotionResult.Result.RecoveryToken);
            if (!sessionResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(sessionResult.ToInvokeResult());
            if (sessionResult.Result == null || String.IsNullOrWhiteSpace(sessionResult.Result.ContinuityToken)) return InvokeResult<ContinuitySessionView>.FromError("Could not establish the provisional continuity session.");

            Response.Cookies.Delete(ContinuityCookieName, CreateDeleteCookieOptions());
            Response.Cookies.Append(ContinuityCookieName, sessionResult.Result.ContinuityToken, CreateCookieOptions(sessionResult.Result.IdentityExpiresUtc));
            return InvokeResult<ContinuitySessionView>.Create(ContinuitySessionView.FromSession(sessionResult.Result));
        }

        [AllowProvisionalIdentity]
        [HttpPost("/api/continuity/account")]
        public async Task<InvokeResult<EstablishProvisionalAccountResponse>> EstablishAccountAsync([FromBody] EstablishProvisionalAccountRequest request)
        {
            SetNoStore();
            var identityResult = GetProvisionalIdentity();
            if (!identityResult.Successful) return InvokeResult<EstablishProvisionalAccountResponse>.FromInvokeResult(identityResult.ToInvokeResult());
            return await _provisionalEnvironmentManager.EstablishAccountAsync(request, identityResult.Result.AppUserId);
        }

        [AllowAnonymousVisitor]
        [AllowProvisionalIdentity]
        [HttpPost("/api/continuity/reset")]
        public async Task<InvokeResult<ContinuitySessionView>> ResetAsync()
        {
            SetNoStore();
            var identityResult = await GetContinuityIdentityAsync();
            if (!identityResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(identityResult.ToInvokeResult());

            Request.Cookies.TryGetValue(ContinuityCookieName, out var continuityToken);
            var clearResult = await _conversationManager.ClearAsync(identityResult.Result.ActorId);
            if (!clearResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(clearResult);

            InvokeResult<ContinuitySessionResponse> resetResult;
            if (String.Equals(identityResult.Result.IdentityStage, ClaimsFactory.RegisteredIdentityStage, StringComparison.Ordinal))
            {
                Response.Cookies.Delete(ContinuityCookieName, CreateDeleteCookieOptions());
                resetResult = await _continuitySessionManager.ResolveAsync(null);
            }
            else
            {
                resetResult = await _continuitySessionManager.ResetAsync(identityResult.Result.ActorId, identityResult.Result.IdentityStage, continuityToken);
            }
            if (!resetResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(resetResult.ToInvokeResult());
            if (resetResult.Result == null || String.IsNullOrWhiteSpace(resetResult.Result.ContinuityToken)) return InvokeResult<ContinuitySessionView>.FromError("Could not establish a fresh continuity session.");

            Response.Cookies.Delete(ContinuityCookieName, CreateDeleteCookieOptions());
            Response.Cookies.Append(ContinuityCookieName, resetResult.Result.ContinuityToken, CreateCookieOptions(resetResult.Result.IdentityExpiresUtc));
            return InvokeResult<ContinuitySessionView>.Create(ContinuitySessionView.FromSession(resetResult.Result));
        }

        private InvokeResult<RestrictedIdentity> GetVisitorIdentity()
        {
            var identityResult = GetRestrictedIdentity();
            if (!identityResult.Successful) return identityResult;
            return String.Equals(identityResult.Result.IdentityStage, ClaimsFactory.VisitorIdentityStage, StringComparison.Ordinal)
                ? identityResult
                : InvokeResult<RestrictedIdentity>.FromError("A Visitor identity is required.");
        }

        private InvokeResult<RestrictedIdentity> GetProvisionalIdentity()
        {
            var identityResult = GetRestrictedIdentity();
            if (!identityResult.Successful) return identityResult;
            if (!String.Equals(identityResult.Result.IdentityStage, ClaimsFactory.ProvisionalIdentityStage, StringComparison.Ordinal))
                return InvokeResult<RestrictedIdentity>.FromError("A Provisional identity is required.");
            if (String.IsNullOrWhiteSpace(identityResult.Result.AppUserId))
                return InvokeResult<RestrictedIdentity>.FromError("The provisional AppUser claim is required.");
            return identityResult;
        }

        private InvokeResult<RestrictedIdentity> GetRestrictedIdentity()
        {
            var actorId = User?.FindFirst(ClaimsFactory.ActorId)?.Value;
            var identityStage = User?.FindFirst(ClaimsFactory.IdentityStage)?.Value;
            var appUserId = User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (String.IsNullOrWhiteSpace(actorId)) return InvokeResult<RestrictedIdentity>.FromError("The restricted identity actor claim is required.");
            if (!String.Equals(identityStage, ClaimsFactory.VisitorIdentityStage, StringComparison.Ordinal) && !String.Equals(identityStage, ClaimsFactory.ProvisionalIdentityStage, StringComparison.Ordinal)) return InvokeResult<RestrictedIdentity>.FromError("A Visitor or Provisional identity is required.");

            return InvokeResult<RestrictedIdentity>.Create(new RestrictedIdentity { ActorId = actorId, IdentityStage = identityStage, AppUserId = appUserId });
        }

        private async Task<InvokeResult<RestrictedIdentity>> GetContinuityIdentityAsync()
        {
            var restrictedIdentity = GetRestrictedIdentity();
            if (restrictedIdentity.Successful) return restrictedIdentity;

            var appUserId = User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (String.IsNullOrWhiteSpace(appUserId)) return restrictedIdentity;
            if (!Request.Cookies.TryGetValue(ContinuityCookieName, out var provisionalEnvironmentId) || String.IsNullOrWhiteSpace(provisionalEnvironmentId))
                return InvokeResult<RestrictedIdentity>.FromError("The registered continuity workspace cookie is required.");

            var sessionResult = await _continuitySessionManager.GetClaimedSessionAsync(provisionalEnvironmentId, appUserId);
            if (!sessionResult.Successful) return InvokeResult<RestrictedIdentity>.FromInvokeResult(sessionResult.ToInvokeResult());

            return InvokeResult<RestrictedIdentity>.Create(new RestrictedIdentity
            {
                ActorId = sessionResult.Result.ActorId,
                IdentityStage = sessionResult.Result.IdentityStage,
                AppUserId = sessionResult.Result.AppUserId
            });
        }

        private void SetNoStore()
        {
            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";
        }

        private static CookieOptions CreateDeleteCookieOptions()
        {
            return new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None, IsEssential = true, Path = "/" };
        }

        private static CookieOptions CreateCookieOptions(DateTime expiresUtc)
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                IsEssential = true,
                Path = "/",
                Expires = new DateTimeOffset(DateTime.SpecifyKind(expiresUtc, DateTimeKind.Utc))
            };
        }

        private sealed class RestrictedIdentity
        {
            public string ActorId { get; set; }
            public string IdentityStage { get; set; }
            public string AppUserId { get; set; }
        }
    }

    public class ContinuityPromotionRequest
    {
        public bool TermsAndConditionsAccepted { get; set; }
        public string TermsAndConditionsVersion { get; set; }
    }

    public class ContinuityPromotionView
    {
        public string TermsAndConditionsVersion { get; set; }
    }
}
