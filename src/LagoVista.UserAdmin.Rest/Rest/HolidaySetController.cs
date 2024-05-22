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
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class HolidaySetController : LagoVistaBaseController
    {
        private readonly IHolidaySetManager _manager;

        public HolidaySetController(IHolidaySetManager manager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        }

        /// <summary>
        /// Holiday Set - Add
        /// </summary>
        /// <param name="holidaySet"></param>
        [HttpPost("/api/holidayset")]
        public Task<InvokeResult> AddHolidaySetAsync([FromBody] HolidaySet holidaySet)
        {
            return _manager.AddHolidaySetAsync(holidaySet, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Holiday Set - Update
        /// </summary>
        /// <param name="holidaySet"></param>
        /// <returns></returns>
        [HttpPut("/api/holidayset")]
        public Task<InvokeResult> UpdateHolidaySetAsync([FromBody] HolidaySet holidaySet)
        {
            SetUpdatedProperties(holidaySet);
            return _manager.UpdateHolidaySetAsync(holidaySet, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Holiday Set - Seed scheduled down time to an organization.
        /// </summary>
        /// <param name="holidaysetid"></param>
        /// <param name="destinationorgid"></param>
        /// <returns></returns>
        [HttpPut("/api/holidayset/copytoorg/{holidaysetid}/to/{destinationorgid}")]
        public Task<InvokeResult> CopyToOrg(string holidaysetid, string destinationorgid)
        {
            return _manager.CopyToOrgAsync(holidaysetid, destinationorgid, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Holiday Sets - Get for Current Org
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/holidaysets")]
        public Task<ListResponse<HolidaySetSummary>> GetHolidaySetForOrg()
        {
            return _manager.GetAllHolidaySets(OrgEntityHeader, UserEntityHeader, GetListRequestFromHeader());
        }

        /// <summary>
        /// Holiday Set - In Use
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/holidayset/{id}/inuse")]
        public Task<DependentObjectCheckResult> InUseCheckAsync(String id)
        {
            return _manager.CheckHolidaySetInUseAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Holiday Set - Get
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/holidayset/{id}")]
        public async Task<DetailResponse<HolidaySet>> GetHolidaySetAsync(String id)
        {
            var holidaySet = await _manager.GetHolidaySetAsync(id, OrgEntityHeader, UserEntityHeader);

            return DetailResponse<HolidaySet>.Create(holidaySet);
        }

        /// <summary>
        /// Holiday Set - Key In Use
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/holidayset/{key}/keyinuse")]
        public Task<bool> GetHolidaySetKeyInUseAsync(String key)
        {
            return _manager.QueryKeyInUseAsync(key, OrgEntityHeader);
        }

        /// <summary>
        /// Holiday Set - Delete
        /// </summary>
        /// <returns></returns>
        [HttpDelete("/api/holidayset/{id}")]
        public Task<InvokeResult> DeleteHolidaySetAsync(string id)
        {
            return _manager.DeleteHolidaySetAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Holiday Set - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/holidayset/factory")]
        public DetailResponse<HolidaySet> CreateHolidaySet()
        {
            var response = DetailResponse<HolidaySet>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }
    }
}
