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
    public class LocationDiagramController : LagoVistaBaseController
    {
        private readonly ILocationDiagramManager _diagramManager;

        public LocationDiagramController(ILocationDiagramManager diagramManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _diagramManager = diagramManager ?? throw new ArgumentNullException(nameof(diagramManager));
        }


        [HttpPost("/api/org/location/diagram")]
        public Task<InvokeResult> AddLocationAsync([FromBody] LocationDiagram diagram)
        {
            return _diagramManager.AddLocationDiagramAsync(diagram, OrgEntityHeader, UserEntityHeader);
        }

        [HttpPut("/api/org/location/diagram")]
        public Task<InvokeResult> UpdateLocationAsync([FromBody] LocationDiagram diagram)
        {
            return _diagramManager.UpdateLocationDiagramAsync(diagram, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/org/location/diagram/{id}")]
        public async Task<DetailResponse<LocationDiagram>> GetOrgLocation(string id)
        {
            var diagram = await _diagramManager.GetLocationDiagramAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<LocationDiagram>.Create(diagram);
        }

        [HttpGet("/api/org/location/diagrams")]
        public Task<ListResponse<LocationDiagramSummary>> GetDiagrams()
        {
            return _diagramManager.GetLocationDiagramsAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/org/location/diagram/factory")]
        public DetailResponse<LocationDiagram> CreateOrgLocation()
        {
            var location = DetailResponse<LocationDiagram>.Create();
            SetOwnedProperties(location.Model);
            SetAuditProperties(location.Model);
            return location;
        }

        [HttpGet("/api/org/location/diagram/shape/factory")]
        public DetailResponse<LocationDiagramShape> CreateDiagramShape()
        {
            return DetailResponse<LocationDiagramShape>.Create();
        }

        [HttpGet("/api/org/location/diagram/group")]
        public DetailResponse<LocationDiagramShapeGroup> CreateDiagramShapeGroup()
        {
            return DetailResponse<LocationDiagramShapeGroup>.Create();
        }
    }
}
