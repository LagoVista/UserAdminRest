using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.PlatformSupport;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Managers;
using LagoVista.UserAdmin.Models.Account;
using LagoVista.UserAdmin.Models.Orgs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    /// <summary>
    /// Orgs Srevices
    /// </summary>
    [Authorize]
    public class OrgServicesController : LagoVistaBaseController
    {
        IAppUserManager _appUserManager;
        IOrganizationManager _orgManager;

        public OrgServicesController(IAppUserManager appUserManager, IOrganizationManager orgManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _appUserManager = appUserManager;
            _orgManager = orgManager;
        }


        /// <summary>
        /// Orgs Service - Get Orgs for User
        /// </summary>
        /// <param name="accountId"></param>
        /// <returns></returns>
        public async Task<ListResponse<OrganizationAccount>> GetOrgForAccountAsync(String accountId)
        {
            var orgAccount = await _orgManager.GetOrganizationsForAccountAsync(accountId);

            return ListResponse<OrganizationAccount>.Create(orgAccount);
        }

        /// <summary>
        /// Orgs Service - Get Users for Org
        /// </summary>
        /// <param name="orgId"></param>
        /// <returns></returns>
        public async Task<ListResponse<OrganizationAccount>> GetUserForOrgAsync(String orgId)
        {
            var orgAccount = await _orgManager.GetAccountsForOrganizationsAsync(orgId);

            return ListResponse<OrganizationAccount>.Create(orgAccount);
        }
    }
}
