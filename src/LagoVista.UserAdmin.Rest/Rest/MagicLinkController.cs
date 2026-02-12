using LagoVista.Core.Exceptions;
using LagoVista.Core.Interfaces;
using LagoVista.Core.Models;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Interfaces.REpos.Account;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Web.Controllers.Auth
{
    [AllowAnonymous]
    public class MagicLinkController : LagoVistaBaseController
    {
        private readonly IMagicLinkManager _magicLinkManager;
        private readonly IAppConfig _appConfig;

        public MagicLinkController(IMagicLinkManager magicLinkManager, IAppConfig appConfig, UserManager<AppUser> userManager, IAdminLogger logger) 
            : base(userManager, logger)
        {
            _magicLinkManager = magicLinkManager ?? throw new ArgumentNullException(nameof(magicLinkManager));
            _appConfig = appConfig ?? throw new ArgumentNullException(nameof(appConfig));
        }

        // -----------------------------
        // Request link (non-enumerating)
        // -----------------------------
        [HttpPost("/api/auth/securelink/request")]
        public async Task<InvokeResult> RequestMagicLink([FromBody] MagicLinkRequest request)
        {
            // Always 202 (non-enumerating). Service also behaves non-enumerating.
            var ctx = new MagicLinkRequestContext
            {
                IpAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request?.Headers["User-Agent"].ToString(),
                CorrelationId = HttpContext?.TraceIdentifier
            };

            return await _magicLinkManager.RequestSignInLinkAsync(request, ctx);
        }

        // -----------------------------------------------------------------
        // Consume (browser link click): sets cookie session + redirects
        // -----------------------------------------------------------------
        // Example: GET /api/auth/securelink/consume?code=...&returnUrl=/app
        [HttpGet("/api/auth/securelink/consume")]
        public async Task<InvokeResult<UserLoginResponse>>ConsumeGet([FromQuery] string code, [FromQuery] string returnUrl = null)
        {
            var ctx = new MagicLinkConsumeContext
            {
                Channel = MagicLinkAttempt.Channel_Portal,
                IpAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request?.Headers["User-Agent"].ToString(),
            };

            return await _magicLinkManager.ConsumeAsync(code, ctx);
        }

        // -----------------------------------------------------------------
        // Consume (API call): portal or mobile. Mobile returns exchangeCode.
        // -----------------------------------------------------------------
        [HttpPost("/api/auth/securelink/consume")]
        public async Task<InvokeResult<UserLoginResponse>> ConsumePost([FromBody] SecureLinkConsumeRequest request)
        {
            var ctx = new MagicLinkConsumeContext
            {
                Channel = request.Channel,
                IpAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request?.Headers["User-Agent"].ToString(),
                ReturnUrl = request.ReturnUrl
            };

            return await _magicLinkManager.ConsumeAsync(request.Code, ctx);
        }

        // -----------------------------------------------------------------
        // Exchange (mobile): exchangeCode -> AppUser (for JWT issuance)
        // -----------------------------------------------------------------
        [HttpPost("/api/auth/securelink/exchange")]
        public async Task<AuthResponse> Exchange([FromBody] SecureLinkExchangeRequest request)
        {

            var ctx = new MagicLinkExchangeContext
            {
                IpAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request?.Headers["User-Agent"].ToString(),
                CorrelationId = HttpContext?.TraceIdentifier
            };

            var userResult = await _magicLinkManager.ExchangeAsync(request.ExchangeCode, ctx);
            // TODO - need to sort this out.
            throw new NotImplementedException();
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
