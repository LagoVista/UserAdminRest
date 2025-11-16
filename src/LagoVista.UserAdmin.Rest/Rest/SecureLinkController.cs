// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: bbd02262cca8be198d61f5a05b697eec40f072389c897bea7358139c9a0241a3
// IndexVersion: 2
// --- END CODE INDEX META ---
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
