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
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [ApiController]
    public class ContinuityConversationController : ControllerBase
    {
        private const string ContinuityCookieName = "aptix_continuity";

        private readonly IContinuityConversationManager _conversationManager;
        private readonly IContinuitySessionManager _continuitySessionManager;

        public ContinuityConversationController(IContinuityConversationManager conversationManager, IContinuitySessionManager continuitySessionManager)
        {
            _conversationManager = conversationManager ?? throw new ArgumentNullException(nameof(conversationManager));
            _continuitySessionManager = continuitySessionManager ?? throw new ArgumentNullException(nameof(continuitySessionManager));
        }

        [Authorize]
        [AllowAnonymousVisitor]
        [AllowProvisionalIdentity]
        [HttpGet("/api/continuity/conversation")]
        public async Task<InvokeResult<ContinuityConversationResponse>> GetConversationAsync()
        {
            SetNoStore();
            var identityResult = GetRestrictedIdentity();
            if (!identityResult.Successful) return InvokeResult<ContinuityConversationResponse>.FromInvokeResult(identityResult.ToInvokeResult());
            return await _conversationManager.GetAsync(identityResult.Result.ActorId);
        }

        [Authorize]
        [AllowAnonymousVisitor]
        [AllowProvisionalIdentity]
        [HttpPost("/api/continuity/conversation/message")]
        public async Task<InvokeResult<ContinuityConversationResponse>> SendMessageAsync([FromBody] ContinuityConversationMessageRequest request)
        {
            SetNoStore();
            var identityResult = GetRestrictedIdentity();
            if (!identityResult.Successful) return InvokeResult<ContinuityConversationResponse>.FromInvokeResult(identityResult.ToInvokeResult());
            return await _conversationManager.SendAsync(identityResult.Result.ActorId, identityResult.Result.IdentityStage, request);
        }

        [Authorize]
        [AllowAnonymousVisitor]
        [AllowProvisionalIdentity]
        [HttpPost("/api/continuity/reset")]
        public async Task<InvokeResult<ContinuitySessionView>> ResetAsync()
        {
            SetNoStore();
            var identityResult = GetRestrictedIdentity();
            if (!identityResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(identityResult.ToInvokeResult());

            Request.Cookies.TryGetValue(ContinuityCookieName, out var continuityToken);
            var clearResult = await _conversationManager.ClearAsync(identityResult.Result.ActorId);
            if (!clearResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(clearResult);

            var resetResult = await _continuitySessionManager.ResetAsync(identityResult.Result.ActorId, identityResult.Result.IdentityStage, continuityToken);
            if (!resetResult.Successful) return InvokeResult<ContinuitySessionView>.FromInvokeResult(resetResult.ToInvokeResult());
            if (resetResult.Result == null || String.IsNullOrWhiteSpace(resetResult.Result.ContinuityToken)) return InvokeResult<ContinuitySessionView>.FromError("Could not establish a fresh continuity session.");

            Response.Cookies.Delete(ContinuityCookieName, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, IsEssential = true, Path = "/" });
            Response.Cookies.Append(ContinuityCookieName, resetResult.Result.ContinuityToken, CreateCookieOptions(resetResult.Result.IdentityExpiresUtc));
            return InvokeResult<ContinuitySessionView>.Create(ContinuitySessionView.FromSession(resetResult.Result));
        }

        private InvokeResult<RestrictedIdentity> GetRestrictedIdentity()
        {
            var actorId = User?.FindFirst(ClaimsFactory.ActorId)?.Value;
            var identityStage = User?.FindFirst(ClaimsFactory.IdentityStage)?.Value;

            if (String.IsNullOrWhiteSpace(actorId)) return InvokeResult<RestrictedIdentity>.FromError("The restricted identity actor claim is required.");
            if (!String.Equals(identityStage, ClaimsFactory.VisitorIdentityStage, StringComparison.Ordinal) && !String.Equals(identityStage, ClaimsFactory.ProvisionalIdentityStage, StringComparison.Ordinal)) return InvokeResult<RestrictedIdentity>.FromError("A Visitor or Provisional identity is required.");

            return InvokeResult<RestrictedIdentity>.Create(new RestrictedIdentity { ActorId = actorId, IdentityStage = identityStage });
        }

        private void SetNoStore()
        {
            Response.Headers.CacheControl = "no-store";
            Response.Headers.Pragma = "no-cache";
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

        private sealed class RestrictedIdentity
        {
            public string ActorId { get; set; }
            public string IdentityStage { get; set; }
        }
    }
}
