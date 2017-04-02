using LagoVista.IoT.Web.Common.Controllers;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Text;
using LagoVista.Core.PlatformSupport;
using LagoVista.UserManagement.Models.Account;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using LagoVista.Core.Networking.Models;
using System.Threading.Tasks;

namespace LagoVista.UserManagement.Rest
{
    [Authorize]
    [Route("api/user")]
    public class UserServices : LagoVistaBaseController
    {
        public UserServices(IAppUserManager appUserManager, UserManager<AppUser> userManager, ILogger logger) : base(userManager, logger)
        {

        }

        [HttpGet("{id}")]
        public async Task<APIResponse<AppUser>> GetUserAsync(String id)
        {
            throw new NotImplementedException();

        }
    }
}
