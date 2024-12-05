using LagoVista.Core;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Runtime.Core.Users;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Orgs;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class DistroListController : LagoVistaBaseController
    {
        private readonly IDistributionManager _distorManager;
        private readonly ISystemUsers _systemUser;

        public DistroListController(IDistributionManager distroManager, ISystemUsers systemUsers,  UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _distorManager = distroManager ?? throw new ArgumentNullException(nameof(distroManager));
            _systemUser = systemUsers ?? throw new ArgumentNullException(nameof(systemUsers));
        }

        /// <summary>
        /// Distro List - Add
        /// </summary>
        /// <param name="distro"></param>
        [HttpPost("/api/distro")]
        public Task<InvokeResult> AddDistroListAsync([FromBody] DistroList distro)
        {
            return _distorManager.AddListAsync(distro, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Distro List - Update
        /// </summary>
        /// <param name="distro"></param>
        /// <returns></returns>
        [HttpPut("/api/distro")]
        public Task<InvokeResult> UpdateDistroListAsync([FromBody] DistroList distro)
        {
            SetUpdatedProperties(distro);
            return _distorManager.UpdatedListAsync(distro, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Distro Lists - Get for Current Org
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/distros")]
        public Task<ListResponse<DistroListSummary>> GetDistroListForOrg()
        {
            return _distorManager.GetListsForOrgAsync(OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        /// <summary>
        /// Distro Lists - Get for Current Org
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/distros/customer/{customerid}")]
        public Task<ListResponse<DistroListSummary>> GetDistroListForCustomer(string customerid)
        {
            return _distorManager.GetListsForCustomerAsync(customerid, OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        /// <summary>
        /// Distro List - In Use
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/distro/{id}/inuse")]
        public Task<DependentObjectCheckResult> InUseCheckAsync(String id)
        {
            return _distorManager.CheckInUse(id, OrgEntityHeader, UserEntityHeader);
        }


        /// <summary>
        /// Distro List - In Use
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/distro/{id}/sendconfirmmessage")]
        public Task<InvokeResult> SendTestAsync(String id)
        {
            return _distorManager.SendTestAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [AllowAnonymous]
        [HttpGet("/api/distro/{id}/confirm/external/{contactid}/{contactmethod}")]
        public async Task<IActionResult> ConfirmExternalContact(string orgId, string id, string contactid, string contactmethod)
        {
            var result = await _distorManager.ConfirmExternalContact(id, contactid, contactmethod);

            return Content($"<html>{result.Result}</html>", "text/html");
        }

        [AllowAnonymous]
        [HttpGet("/api/distro/{id}/confirm/appuser/{appuserid}/{contactmethod}")]
        public async Task<IActionResult> ConfirmAppUser(string id, string appuserid, string contactmethod)
        {
            var result = await _distorManager.ConfirmExternalContact(id, appuserid, contactmethod);

            return Content($"<html>{result.Result}</html>", "text/html");
        }


        /// <summary>
        /// Distro List - Get
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/distro/{id}")]
        public async Task<DetailResponse<DistroList>> GetDistroListAsync(String id)
        {
            var distroList = await _distorManager.GetListAsync(id, OrgEntityHeader, UserEntityHeader);

            return DetailResponse<DistroList>.Create(distroList);
        }

        /// <summary>
        /// Distro List - Key In Use
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/distro/{key}/keyinuse")]
        public Task<bool> GetDistroKeyInUseAsync(String key)
        {
            return _distorManager.QueryKeyInUseAsync(key, CurrentOrgId);
        }

        /// <summary>
        /// Distro List - Delete
        /// </summary>
        /// <returns></returns>
        [HttpDelete("/api/distro/{id}")]
        public Task<InvokeResult> DeleteDistroListAsync(string id)
        {
            return _distorManager.DeleteListAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Distro List - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/distro/factory")]
        public DetailResponse<DistroList> CreateDistroList()
        {
            var response = DetailResponse<DistroList>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }

        [HttpGet("/api/distro/externalcontact/factory")]
        public DetailResponse<ExternalContact> CreateExternalContact()
        {
            var response = DetailResponse<ExternalContact>.Create();
            return response;
        }
    }
}
