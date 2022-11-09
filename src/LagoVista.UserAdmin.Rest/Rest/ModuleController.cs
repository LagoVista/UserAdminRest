using LagoVista.Core;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Security;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{    
    [Authorize]
    public class ModuleController : LagoVistaBaseController
    {
        private readonly IModuleManager _moduleManager;

        public ModuleController(IModuleManager moduleManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _moduleManager = moduleManager ?? throw new ArgumentNullException();
        }

        /// <summary>
        /// module List - Add
        /// </summary>
        /// <param name="module"></param>
        [HttpPost("/api/module")]
        public Task<InvokeResult> AddmoduleListAsync([FromBody] Module module)
        {
            return _moduleManager.AddModuleAsync(module, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// module List - Update
        /// </summary>
        /// <param name="module"></param>
        /// <returns></returns>
        [HttpPut("/api/module")]
        public Task<InvokeResult> UpdateModuleListAsync([FromBody] Module module)
        {
            SetUpdatedProperties(module);
            return _moduleManager.UpdateModuleAsync(module, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// module Lists - Get for Current Org
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/modules")]
        public Task<List<ModuleSummary>> GetAllModulesAsync()
        {
            return _moduleManager.GetAllModulesAsync(OrgEntityHeader, UserEntityHeader);
        }

        
        /// <summary>
        /// module - Get
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/module/{id}")]
        public async Task<DetailResponse<Module>> GetModuleAsync(String id)
        {
            var module = await _moduleManager.GetModuleAsync(id, OrgEntityHeader, UserEntityHeader);

            return DetailResponse<Module>.Create(module);
        }
        
        /// <summary>
        /// Module - Delete
        /// </summary>
        /// <returns></returns>
        [HttpDelete("/api/module/{id}")]
        public Task<InvokeResult> DeletemMduleListAsync(string id)
        {
            return _moduleManager.DeleteModuleAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Module - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/module/factory")]
        public DetailResponse<Module> CreateNewModule()
        {
            var response = DetailResponse<Module>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }

        /// <summary>
        /// Area - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/module/area/factory")]
        public DetailResponse<Area> CreateNewArea()
        {
            return DetailResponse<Area>.Create();
        }

        /// <summary>
        /// Page - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/module/page/factory")]
        public DetailResponse<Page> CreateNewPage()
        {
            return DetailResponse<Page>.Create();
        }

        /// <summary>
        /// Feature - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/module/feature/factory")]
        public DetailResponse<Feature> CreateNewFeature()
        {
            return DetailResponse<Feature>.Create();
        }
    }
}
