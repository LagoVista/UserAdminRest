using LagoVista.Core.Exceptions;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{

    public class SecureLinksController : Controller
    {
        private readonly ISecureLinkManager _secureLinkMManager;
        public SecureLinksController(ISecureLinkManager secureLinkMManager)
        {
            _secureLinkMManager = secureLinkMManager ?? throw new ArgumentNullException(nameof(secureLinkMManager));
        }

        [HttpGet("/api/links/{orgid}/{linkid}")]
        public async Task<IActionResult> HandleLink(string orgid, string linkid)
        {
            var result = await _secureLinkMManager.GetSecureLinkAsync(orgid, linkid);
            if(result.Successful)
                return Redirect(result.Result);

            throw new NotAuthenticatedException(result.Result);
        }
    }
}
