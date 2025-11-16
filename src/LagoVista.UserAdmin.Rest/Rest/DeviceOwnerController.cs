// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: c78fa192502bef411f40c47317fdc5bf713659d046a718fb3e0283db33849119
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.Core.Exceptions;
using LagoVista.Core.Interfaces;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.DeviceManagement.Core;
using LagoVista.IoT.DeviceManagement.Core.Managers;
using LagoVista.IoT.DeviceManagement.Core.Repos;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Interfaces.Repos.Account;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using Newtonsoft.Json;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    [SystemAdmin]
    public class DeviceOwnerController : LagoVistaBaseController
    {
        IDeviceOwnerRepo _deviceOwnerRepo;
        IDeviceManager _deviceManager;
        IDeviceRepositoryManager _deviceRepoManager;

        public DeviceOwnerController(IOrganizationManager orgManager, UserManager<AppUser> userManager, IDeviceManager deviceManager, IDeviceRepositoryManager deviceRepoManager, IDeviceOwnerRepo deviceOwnerRepo, ITimeZoneServices timeZoneServices, IAdminLogger logger) : base(userManager, logger)
        {
            _deviceOwnerRepo = deviceOwnerRepo ?? throw new ArgumentNullException(nameof(deviceOwnerRepo));
            _deviceManager = deviceManager ?? throw new ArgumentNullException(nameof(deviceManager));
            _deviceRepoManager = deviceRepoManager ?? throw new ArgumentNullException(nameof(deviceRepoManager));
        }

        [HttpGet("/api/sysadmin/deviceownerusers")]
        public Task<ListResponse<DeviceOwnerUserSummary>> GetAllUsersAsync()
        {
            return _deviceOwnerRepo.GetAllAsync(GetListRequestFromHeader());
        }

        [HttpGet("/api/sysadmin/deviceowneruser/{orgid}/{id}")]
        public async Task<DetailResponse<DeviceOwnerUser>> GetDeviceOnwerUser(string orgid, string id)
        {
            var owneduser =  await _deviceOwnerRepo.FindByIdAsync(id);
            if (owneduser != null)
                return DetailResponse<DeviceOwnerUser>.Create(owneduser);

            throw new RecordNotFoundException(nameof(DeviceOwnerUser), id);
        }

        [HttpPost("/api/sysadmin/deviceowner")]
        public Task SaveDeviceOwner(DeviceOwnerUser user)
        {
            return _deviceOwnerRepo.AddUserAsync(user);
        }

        [HttpPut("/api/sysadmin/deviceowner")]
        public Task UpdateDeviceOwner(DeviceOwnerUser user)
        {
            return _deviceOwnerRepo.UpdateUserAsync(user);
        }

        [HttpGet("/api/sysadmin/deviceowner/factory")]
        public DetailResponse<DeviceOwnerUser> CreateUserAsync()
        {
            return DetailResponse<DeviceOwnerUser>.Create();
        }

        [HttpDelete("/api/sysadmin/deviceowneruser/{orgid}/{id}")]
        public async Task<InvokeResult> DeleteDeviceOwneruser(string orgid, string id)
        {
            var user = await _deviceOwnerRepo.FindByIdAsync(id);
            if(user != null)
            {
                foreach (var ownedDevice in user.Devices)
                {
                    var repo = await _deviceRepoManager.GetDeviceRepositoryWithSecretsAsync(ownedDevice.DeviceRepository.Id, user.OwnerOrganization, user.ToEntityHeader());
                    var device = await _deviceManager.GetDeviceByIdAsync(repo, ownedDevice.Device.Id, user.OwnerOrganization, user.ToEntityHeader());
                    device.Result.DeviceOwner = null;
                    await _deviceManager.UpdateDeviceAsync(repo, device.Result, user.OwnerOrganization, user.ToEntityHeader());
                }
            }

            return await _deviceOwnerRepo.DeleteUserAsync(orgid, id);
        }

    }
}
