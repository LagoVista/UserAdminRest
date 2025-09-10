using DocumentFormat.OpenXml.Office2013.PowerPoint.Roaming;
using DocumentFormat.OpenXml.Wordprocessing;
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
using RingCentral;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [Authorize]
    public class LocationDiagramController : LagoVistaBaseController
    {
        private readonly ILocationDiagramManager _diagramManager;

        public LocationDiagramController(ILocationDiagramManager diagramManager,UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
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


        [HttpDelete("/api/org/location/diagram/{id}")]
        public Task<InvokeResult> DeleteOrgLocation(string id)
        {
            return _diagramManager.DeleteLocationDiagramAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        [HttpGet("/api/org/location/diagrams")]
        public Task<ListResponse<LocationDiagramSummary>> GetDiagrams()
        {
            return _diagramManager.GetLocationDiagramsAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }


        [HttpGet("/api/org/location/diagram/factory")]
        public DetailResponse<LocationDiagram> CreateDiagram()
        {
            var location = DetailResponse<LocationDiagram>.Create();
            SetOwnedProperties(location.Model);
            SetAuditProperties(location.Model);
            location.Model.Layers.Add(new LocationDiagramLayer()
            {
                Name = "Layer 1",
                Key = "layer1"
            });

            return location;
        }

        [HttpGet("/api/org/location/diagram/shape/factory")]
        public DetailResponse<LocationDiagramShape> CreateDiagramShape()
        {
            return DetailResponse<LocationDiagramShape>.Create();
        }

        [HttpGet("/api/org/location/diagram/group/factory")]
        public DetailResponse<LocationDiagramShapeGroup> CreateDiagramShapeGroup()
        {
            return DetailResponse<LocationDiagramShapeGroup>.Create();
        }


        [HttpGet("/api/org/location/diagram/layer/factory")]
        public DetailResponse<LocationDiagramLayer> CreateDiagramLayer()
        {
            return DetailResponse<LocationDiagramLayer>.Create();
        }
    }
}
