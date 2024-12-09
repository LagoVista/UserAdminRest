using LagoVista.Core.Exceptions;
using LagoVista.UserAdmin.Interfaces.Managers;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    public class SecureLinkController : Controller
    {
        private readonly ISecureLinkManager _secureLinkManager;
        public  SecureLinkController(ISecureLinkManager secureLinkManager)
        {
            _secureLinkManager = secureLinkManager ?? throw new ArgumentNullException(nameof(secureLinkManager));
        }

        [HttpGet("/api/links/{orgid}/{linkid}")]
        public async Task<IActionResult> GetSecureLink(string orgid, string linkid)
        {
            var result = await _secureLinkManager.GetSecureLinkAsync(orgid, linkid);
            if (result.Successful)
            {
                return Redirect(result.Result);
            }

            throw new NotAuthorizedException(result.ErrorMessage);
        }
    }
}
