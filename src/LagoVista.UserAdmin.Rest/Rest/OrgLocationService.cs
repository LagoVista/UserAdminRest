using LagoVista.Core;
using LagoVista.Core.Interfaces;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.MediaServices.Interfaces;
using LagoVista.MediaServices.Managers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Interfaces.Repos.Orgs;
using LagoVista.UserAdmin.Models.Orgs;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{

    [Authorize]
    public class OrgLocationService : LagoVistaBaseController
    {
        private readonly IOrganizationManager _orgManager;
        private readonly ITimeZoneServices _timeZoneServices;
        private readonly IOrganizationRepo _orgRepo;
        private readonly IMediaServicesManager _mediaServicesManager;

        public OrgLocationService(IOrganizationManager orgManager, UserManager<AppUser> userManager, IOrganizationRepo orgRepo, IMediaServicesManager mediaServicesManager, ITimeZoneServices timeZoneServices, IAdminLogger logger) : base(userManager, logger)
        {
            _orgManager = orgManager ?? throw new ArgumentNullException(nameof(orgManager));
            _timeZoneServices = timeZoneServices ?? throw new ArgumentNullException(nameof(timeZoneServices));
            _orgRepo = orgRepo ?? throw new ArgumentNullException(nameof(orgRepo));
            _mediaServicesManager = mediaServicesManager ?? throw new ArgumentNullException(nameof(mediaServicesManager));
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
            var form = DetailResponse<OrgLocation>.Create(org);
            form.View["timeZone"].Options = _timeZoneServices.GetTimeZones().Select(tz => new EnumDescription() { Key = tz.Id, Label = tz.DisplayName, Name = tz.DisplayName }).ToList();
            return form;
        }

        [HttpGet("/api/org/locations")]
        public Task<ListResponse<OrgLocationSummary>> GetOrgLocations()
        {
            return _orgManager.GetLocationsForOrganizationsAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }

        [HttpPost("/api/org/location/{id}/diagram")]
        public async Task<InvokeResult> AddDiagramLocation(string id, [FromBody] OrgLocationDiagramReference reference)
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
            if (diagramReference != null)
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


        [AllowAnonymous]
        [HttpGet("/api/org/{orgid}/logo/light")]
        public async Task<IActionResult> DownloadLightLogo(string orgid)
        {
            var lastMod = String.Empty;
            if (!String.IsNullOrEmpty(Request.Headers["If-Modified-Since"]))
            {
                CultureInfo provider = CultureInfo.InvariantCulture;
                lastMod = DateTime.ParseExact(Request.Headers["If-Modified-Since"], "r", provider).ToJSONString();
            }

            String mediaResourceId = null;
            var org = await _orgRepo.GetOrganizationAsync(orgid);
            if (!EntityHeader.IsNullOrEmpty(org.LightLogo))
            {
                mediaResourceId = org.LightLogo.Id;
            }

            if (!String.IsNullOrEmpty(mediaResourceId))
            {
                var response = await _mediaServicesManager.GetPublicResourceRecordAsync(orgid, mediaResourceId, lastMod);
                if (response.NotModified)
                {
                    return StatusCode(304);
                }

                var ms = new MemoryStream(response.ImageBytes);
                var idx = 1;
                foreach (var timing in response.Timings)
                {
                    Response.Headers.Add($"x-{idx++}-{timing.Key}", $"{timing.Ms}ms");
                }

                Response.Headers[HeaderNames.CacheControl] = "public";
                Response.Headers[HeaderNames.LastModified] = new[] { response.LastModified.ToDateTime().ToString("R") }; // Format RFC1123

                return File(ms, response.ContentType, response.FileName);
            }
            else
            {
                return Redirect("https://nuviot.blob.core.windows.net/cdn/nuviot-blue.png");
            }
        }


        [AllowAnonymous]
        [HttpGet("/api/org/{orgid}/logo/dark")]
        public async Task<IActionResult> DownloadDarkLogo(string orgid)
        {
            var lastMod = String.Empty;
            if (!String.IsNullOrEmpty(Request.Headers["If-Modified-Since"]))
            {
                CultureInfo provider = CultureInfo.InvariantCulture;
                lastMod = DateTime.ParseExact(Request.Headers["If-Modified-Since"], "r", provider).ToJSONString();
            }

            String mediaResourceId = null;
            var org = await _orgRepo.GetOrganizationAsync(orgid);
            if (!EntityHeader.IsNullOrEmpty(org.DarkLogo))
            {
                mediaResourceId = org.DarkLogo.Id;
            }

            if (!String.IsNullOrEmpty(mediaResourceId))
            {
                var response = await _mediaServicesManager.GetPublicResourceRecordAsync(orgid, mediaResourceId, lastMod);
                if (response.NotModified)
                {
                    return StatusCode(304);
                }

                var ms = new MemoryStream(response.ImageBytes);
                var idx = 1;
                foreach (var timing in response.Timings)
                {
                    Response.Headers.Add($"x-{idx++}-{timing.Key}", $"{timing.Ms}ms");
                }

                Response.Headers[HeaderNames.CacheControl] = "public";
                Response.Headers[HeaderNames.LastModified] = new[] { response.LastModified.ToDateTime().ToString("R") }; // Format RFC1123

                return File(ms, response.ContentType, response.FileName);
            }
            else
            {
                return Redirect("https://nuviot.blob.core.windows.net/cdn/nuviot-blue.png");
            }
        }

        [AllowAnonymous]
        [HttpGet("/api/org/{orgid}/theme")]
        public Task<InvokeResult<BasicTheme>> GetTheme(string orgid)
        {
            return _orgManager.GetBasicThemeForOrgAsync(orgid);
        }
    }
}
