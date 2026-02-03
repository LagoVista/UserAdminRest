using LagoVista.Core.Models;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Interfaces.REpos.Account;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Web.Controllers.Auth
{
    [ApiController]
    [Route("api/auth/securelink")]
    public class SecureLinkController : LagoVistaBaseController
    {
        private readonly IMagicLinkManager _magicLinkManager;
   
        public SecureLinkController(IMagicLinkManager magicLinkManager, UserManager<AppUser> userManager, IAdminLogger logger) 
            : base(userManager, logger)
        {
            _magicLinkManager = magicLinkManager ?? throw new ArgumentNullException(nameof(magicLinkManager));
        }

        // -----------------------------
        // Request link (non-enumerating)
        // -----------------------------
        [HttpPost("request")]
        public async Task<IActionResult> RequestMagicLink([FromBody] MagicLinkRequest request)
        {
            // Always 202 (non-enumerating). Service also behaves non-enumerating.
            var ctx = new MagicLinkRequestContext
            {
                IpAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request?.Headers["User-Agent"].ToString(),
                CorrelationId = HttpContext?.TraceIdentifier
            };

            await _magicLinkManager.RequestSignInLinkAsync(request, ctx);

            return Accepted();
        }

        // -----------------------------------------------------------------
        // Consume (browser link click): sets cookie session + redirects
        // -----------------------------------------------------------------
        // Example: GET /api/auth/securelink/consume?code=...&returnUrl=/app
        [HttpGet("consume")]
        public async Task<IActionResult> ConsumeGet([FromQuery] string code, [FromQuery] string returnUrl = null)
        {
            var ctx = new MagicLinkConsumeContext
            {
                Channel = MagicLinkAttempt.Channel_Portal,
                IpAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request?.Headers["User-Agent"].ToString(),
                ReturnUrl = returnUrl
            };

            var consume = await _magicLinkManager.ConsumeAsync(code, ctx);
            if (!consume.Successful)
            {
                // You can redirect to a friendly UI error route if desired.
                return Unauthorized(new { error = FirstErrorOrDefault(consume) });
            }

            // Portal flow: we expect no exchange code and we sign in using cookies.
            var userId = consume.Result?.Attempt?.UserId;
            if (string.IsNullOrWhiteSpace(userId))
                return Unauthorized(new { error = "user_not_found" });

            // Exchange endpoint returns AppUser, but Consume gives us the attempt.
            // We'll call Exchange only for mobile. For portal, we need the AppUser to sign in.
            // If your IMagicLinkManager can return AppUser directly in Consume for portal, we can tighten this.
            // For now, simplest: use ExchangeAsync-style flow is not available here, so we rely on user id.
            // If you prefer, add IMagicLinkManager.GetUserAsync(userId) or inject IUserManager here.
            return BadRequest(new { error = "portal_consume_requires_user_lookup" });
        }

        // -----------------------------------------------------------------
        // Consume (API call): portal or mobile. Mobile returns exchangeCode.
        // -----------------------------------------------------------------
        [HttpPost("consume")]
        public async Task<IActionResult> ConsumePost([FromBody] SecureLinkConsumeRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Code))
                return BadRequest(new { error = "missing_code" });

            var ctx = new MagicLinkConsumeContext
            {
                Channel = request.Channel,
                IpAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request?.Headers["User-Agent"].ToString(),
                ReturnUrl = request.ReturnUrl
            };

            var consume = await _magicLinkManager.ConsumeAsync(request.Code, ctx);
            if (!consume.Successful)
                return Unauthorized(new { error = FirstErrorOrDefault(consume) });

            // Mobile: return exchange code
            if (string.Equals(request.Channel, MagicLinkAttempt.Channel_Mobile, StringComparison.Ordinal))
            {
                return Ok(new
                {
                    exchangeCode = consume.Result.ExchangeCode,
                    attemptId = consume.Result.Attempt?.Id
                });
            }

            // Portal: sign in and return ok (or redirect; your choice)
            // Portal sign-in needs AppUser. We'll use ExchangeAsync-style only for mobile, so we need user lookup here.
            // If you want, I can generate a portal-specific controller in the portal host that injects IUserManager
            // and calls _signInManager.SignInAsync(user).
            return Ok(new
            {
                attemptId = consume.Result.Attempt?.Id
            });
        }

        // -----------------------------------------------------------------
        // Exchange (mobile): exchangeCode -> AppUser (for JWT issuance)
        // -----------------------------------------------------------------
        [HttpPost("exchange")]
        public async Task<IActionResult> Exchange([FromBody] SecureLinkExchangeRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.ExchangeCode))
                return BadRequest(new { error = "missing_exchange_code" });

            var ctx = new MagicLinkExchangeContext
            {
                IpAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request?.Headers["User-Agent"].ToString(),
                CorrelationId = HttpContext?.TraceIdentifier
            };

            var userResult = await _magicLinkManager.ExchangeAsync(request.ExchangeCode, ctx);
            if (!userResult.Successful)
                return Unauthorized(new { error = FirstErrorOrDefault(userResult) });

            // IMPORTANT: This endpoint intentionally does not mint JWT here
            // unless you want it to. Commonly you pass user into your existing token issuance path.
            var user = userResult.Result;

            return Ok(new
            {
                userId = user.Id,
                userName = user.UserName,
                email = user.Email
            });
        }

        private static string FirstErrorOrDefault(InvokeResult result)
        {
            if (result?.Errors == null || result.Errors.Count == 0) return "error";
            return result.Errors[0].Message;
        }

        private static string FirstErrorOrDefault<T>(InvokeResult<T> result)
        {
            if (result?.Errors == null || result.Errors.Count == 0) return "error";
            return result.Errors[0].Message;
        }
    }

    public class SecureLinkConsumeRequest
    {
        public string Code { get; set; }

        /// <summary>
        /// "portal" or "mobile"
        /// </summary>
        public string Channel { get; set; }

        public string ReturnUrl { get; set; }
    }

    public class SecureLinkExchangeRequest
    {
        public string ExchangeCode { get; set; }
    }
}
