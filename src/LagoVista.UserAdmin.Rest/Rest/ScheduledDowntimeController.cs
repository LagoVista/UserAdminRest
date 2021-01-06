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
    public class ScheduledDowntimeController : LagoVistaBaseController
    {
        readonly IScheduledDowntimeManager _manager;

        public ScheduledDowntimeController(IScheduledDowntimeManager manager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        }


        /// <summary>
        /// Scheduled Downtime - Add
        /// </summary>
        /// <param name="scheduledDowntime"></param>
        [HttpPost("/api/scheduleddowntime")]
        public Task<InvokeResult> AddScheduledDowntimeAsync([FromBody] ScheduledDowntime scheduledDowntime)
        {
            return _manager.AddScheduledDowntimeAsync(scheduledDowntime, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Scheduled Downtime - Update
        /// </summary>
        /// <param name="scheduledDowntime"></param>
        /// <returns></returns>
        [HttpPut("/api/scheduleddowntime")]
        public Task<InvokeResult> UpdateScheduledDowntimeAsync([FromBody] ScheduledDowntime scheduledDowntime)
        {
            SetUpdatedProperties(scheduledDowntime);
            return _manager.UpdateScheduledDowntimeAsync(scheduledDowntime, OrgEntityHeader, UserEntityHeader);
        }


        /// <summary>
        /// Scheduled Downtimes - Get for Current Org
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/scheduleddowntimes")]
        public Task<ListResponse<ScheduledDowntimeSummary>> GetScheduledDowntimeForOrg()
        {
            return _manager.GetScheduledDowntimesForOrgAsync(OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        /// <summary>
        /// Scheduled Downtime - In Use
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/scheduleddowntime/{id}/inuse")]
        public Task<DependentObjectCheckResult> InUseCheckAsync(String id)
        {
            return _manager.CheckScheduledDowntimeInUseAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Scheduled Downtime - Get
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/scheduleddowntime/{id}")]
        public async Task<DetailResponse<ScheduledDowntime>> GetScheduledDowntimeAsync(String id)
        {
            var ScheduledDowntime = await _manager.GetScheduledDowntimeAsync(id, OrgEntityHeader, UserEntityHeader);

            return DetailResponse<ScheduledDowntime>.Create(ScheduledDowntime);
        }

        /// <summary>
        /// Scheduled Downtime - Key In Use
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/scheduleddowntime/{key}/keyinuse")]
        public Task<bool> GetScheduledDowntimeKeyInUseAsync(String key)
        {
            return _manager.QueryKeyInUseAsync(key, OrgEntityHeader);
        }

        /// <summary>
        /// Scheduled Downtime - Delete
        /// </summary>
        /// <returns></returns>
        [HttpDelete("/api/scheduleddowntime/{id}")]
        public Task<InvokeResult> DeleteScheduledDowntimeAsync(string id)
        {
            return _manager.DeleteScheduledDowntimeAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Scheduled Downtime - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/scheduleddowntime/factory")]
        public DetailResponse<ScheduledDowntime> CreateScheduledDowntime()
        {
            var response = DetailResponse<ScheduledDowntime>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }


        /// <summary>
        /// Scheduled Downtime - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/scheduleddowntime/period/factory")]
        public DetailResponse<ScheduledDowntimePeriod> CreateScheduledDowntimePeriod()
        {
            var response = DetailResponse<ScheduledDowntimePeriod>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            return response;
        }
    }
}
