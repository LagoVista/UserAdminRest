using LagoVista.Core.Interfaces;
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
using System.Linq;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    
    [Authorize]
    public class OrgLocationService : LagoVistaBaseController
    {
        private readonly IOrganizationManager _orgManager;
        private readonly ITimeZoneServices _timeZoneServices;

        public OrgLocationService( IOrganizationManager orgManager, UserManager<AppUser> userManager, ITimeZoneServices timeZoneServices, IAdminLogger logger) : base(userManager, logger)
        {
            _orgManager = orgManager ?? throw new ArgumentNullException(nameof(orgManager));
            _timeZoneServices = timeZoneServices ?? throw new ArgumentNullException(nameof(timeZoneServices));
        }

        [HttpPost("/api/org/location/")]
        public Task<InvokeResult> AddLocationAsync([FromBody] OrgLocation location)
        {
            return _orgManager.AddLocationAsync(location, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPut("/api/org/location/")]
        public Task<InvokeResult> UpdateLocationAsync([FromBody] OrgLocation location)
        {
            return _orgManager.UpdateLocationAsync(location, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/org/location/{id}")]
        public async Task<DetailResponse<OrgLocation>> GetOrgLocation(string id)
        {
            var org = await _orgManager.GetOrgLocationAsync(id, OrgEntityHeader, UserEntityHeader);
            var form =  DetailResponse<OrgLocation>.Create(org);
            form.View["timeZone"].Options = _timeZoneServices.GetTimeZones().Select(tz => new EnumDescription() { Key = tz.Id, Label = tz.DisplayName, Name = tz.DisplayName }).ToList();
            return form;
        }

        [HttpGet("/api/org/locations")]
        public Task<ListResponse<OrgLocationSummary>> GetOrgLocations()
        {
            return _orgManager.GetLocationsForOrganizationsAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/api/org/location/{id}/diagram")]
        public async Task<InvokeResult> AddDiagramLocation(string id, [FromBody]  OrgLocationDiagramReference reference)
        {
            var location = await _orgManager.GetOrgLocationAsync(id, OrgEntityHeader, UserEntityHeader);
            location.DiagramReferences.Add(reference);
            return await UpdateLocationAsync(location);
        }

        [HttpPut("/api/org/location/{id}/diagram")]
        public async Task<InvokeResult> UpdateDiagramLocation(string id, [FromBody] OrgLocationDiagramReference reference)
        {
            var location = await _orgManager.GetOrgLocationAsync(id, OrgEntityHeader, UserEntityHeader);
            var diagramReference = location.DiagramReferences.FirstOrDefault(drg => drg.Id == reference.Id);
            if(diagramReference != null)
                location.DiagramReferences.Remove(diagramReference);

            location.DiagramReferences.Add(reference);

            return await UpdateLocationAsync(location);
        }

        [HttpDelete("/api/org/location/{id}/diagram/{refid}")]
        public async Task<InvokeResult> UpdateDiagramLocation(string id, string refid)
        {
            var location = await _orgManager.GetOrgLocationAsync(id, OrgEntityHeader, UserEntityHeader);
            var diagramReference = location.DiagramReferences.FirstOrDefault(drg => drg.Id == refid);
            if (diagramReference != null)
                location.DiagramReferences.Remove(diagramReference);

            return await UpdateLocationAsync(location);
        }

        [HttpGet("/api/org/location/factory")]
        public DetailResponse<OrgLocation> CreateOrgLocation()
        {
            var org = DetailResponse<OrgLocation>.Create();
            org.View["timeZone"].Options = _timeZoneServices.GetTimeZones().Select(tz => new EnumDescription() { Key = tz.Id, Label = tz.DisplayName, Name = tz.DisplayName }).ToList();
            SetOwnedProperties(org.Model);
            SetAuditProperties(org.Model);
            org.Model.Organization = org.Model.OwnerOrganization;
            return org;
            
        }
    }
}
