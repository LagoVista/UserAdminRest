using LagoVista.Core.Interfaces;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [SystemAdmin]
    [Authorize]
    public class SecretStoreController : LagoVistaBaseController
    {
        private readonly ISecureStorage _secureStorage;

        public SecretStoreController(UserManager<AppUser> userManager, ISecureStorage secureStorage, IAdminLogger logger) : base(userManager, logger)
        {
            _secureStorage = secureStorage ?? throw new ArgumentNullException(nameof(secureStorage));
        }

        public class SecretStore
        {
            public string SecretBody {get; set;}
        }

        [HttpGet("/api/secretstore/{key}")]
        public async Task<InvokeResult<string>> GetSecretAsync(string key)
        {
            return await _secureStorage.GetSecretAsync(OrgEntityHeader, key, UserEntityHeader);
        }

        [HttpPost("/api/secretstore/{key}")]
        public async Task<InvokeResult<string>> SetSecretAsync(string key, [FromBody] SecretStore value)
        {
            return await _secureStorage.AddSecretAsync(OrgEntityHeader, key, value.SecretBody);
        }
    }
}
