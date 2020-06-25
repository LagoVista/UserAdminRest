using LagoVista.Core;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
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

        public DistroListController(IDistributionManager distroManager,  UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _distorManager = distroManager ?? throw new ArgumentNullException();
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
    }
}
