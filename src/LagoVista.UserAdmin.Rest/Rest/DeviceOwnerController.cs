// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: c78fa192502bef411f40c47317fdc5bf713659d046a718fb3e0283db33849119
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.Core.Exceptions;
using LagoVista.Core.Interfaces;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.DeviceManagement.Core;
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
    [Authorize]
    [SystemAdmin]
    public class DeviceOwnerController : LagoVistaBaseController
    {
        private readonly IDeviceOwnerManager _deviceOwnerManager;

        public DeviceOwnerController(IDeviceOwnerManager deviceOwnerManager,
                                     UserManager<AppUser> userManager,
                                     IAdminLogger logger) : base(userManager, logger)
        {
            _deviceOwnerManager = deviceOwnerManager ?? throw new ArgumentNullException(nameof(deviceOwnerManager));
        }

        [HttpGet("/api/sysadmin/deviceownerusers")]
        public Task<ListResponse<DeviceOwnerUserSummary>> GetAllUsersAsync()
        {
            return _deviceOwnerManager.GetOwnersAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/sysadmin/deviceowneruser/{orgid}/{id}")]
        public async Task<DetailResponse<DeviceOwnerUser>> GetDeviceOnwerUser(string orgid, string id)
        {
            var owner = await _deviceOwnerManager.GetOwnerByIdAsync(id, GetOrganization(orgid), UserEntityHeader);
            if (owner.Successful && owner.Result != null)
                return DetailResponse<DeviceOwnerUser>.Create(owner.Result);

            throw new RecordNotFoundException(nameof(DeviceOwnerUser), id);
        }

        [HttpPost("/api/sysadmin/deviceowner")]
        public Task<InvokeResult> SaveDeviceOwner([FromBody] DeviceOwnerUser user)
        {
            var org = user?.OwnerOrganization ?? OrgEntityHeader;
            return _deviceOwnerManager.CreateOwnerAsync(user, org, UserEntityHeader);
        }

        [HttpPut("/api/sysadmin/deviceowner")]
        public Task<InvokeResult> UpdateDeviceOwner([FromBody] DeviceOwnerUser user)
        {
            var org = user?.OwnerOrganization ?? OrgEntityHeader;
            return _deviceOwnerManager.UpdateOwnerAsync(user, org, UserEntityHeader);
        }

        [HttpGet("/api/sysadmin/deviceowner/factory")]
        public DetailResponse<DeviceOwnerUser> CreateUserAsync()
        {
            return DetailResponse<DeviceOwnerUser>.Create();
        }

        [HttpDelete("/api/sysadmin/deviceowneruser/{orgid}/{id}")]
        public Task<InvokeResult> DeleteDeviceOwneruser(string orgid, string id)
        {
            return _deviceOwnerManager.DeleteOwnerAsync(id, GetOrganization(orgid), UserEntityHeader);
        }

        private EntityHeader GetOrganization(string orgId)
        {
            if (OrgEntityHeader?.Id == orgId)
                return OrgEntityHeader;

            return new EntityHeader
            {
                Id = orgId,
                Text = orgId
            };
        }
    }
}
