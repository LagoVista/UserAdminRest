using LagoVista.Core;
using LagoVista.Core.Exceptions;
using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Security;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{    
    [Authorize]
    public class ModuleController : LagoVistaBaseController
    {
        private readonly IModuleManager _moduleManager;
        private readonly IIUserAccessManager _userAccessManager;

        public ModuleController(IModuleManager moduleManager, IIUserAccessManager userAccessManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _moduleManager = moduleManager ?? throw new ArgumentNullException();
            _userAccessManager = userAccessManager ?? throw new ArgumentNullException(nameof(userAccessManager));
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
        public Task<ListResponse<ModuleSummary>> GetAllModulesAsync()
        {
            return _moduleManager.GetAllModulesAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// module Lists - Get for Current Org
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/modules/my")]
        public Task<List<ModuleSummary>> GetAllModulesForuserAsync()
        {
            return  _userAccessManager.GetUserModulesAsync(UserEntityHeader.Id, OrgEntityHeader.Id);
        }

        /// <summary>
        /// module Lists - Get for Current Org
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/modules/tree")]
        public Task<List<Module>> GetFullAppTreeAsync()
        {
            return _userAccessManager.GetFullAppTreeForUserAsync(UserEntityHeader.Id, OrgEntityHeader.Id);
        }

        /// <summary>
        /// module Lists - Get for a user id
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/modules/user/{userId}")]
        public Task<List<ModuleSummary>> GetModulesForUserAsync(string userId)
        {
            return _userAccessManager.GetUserModulesAsync(userId, OrgEntityHeader.Id);
        }

        /// <summary>
        /// module - Get aras by id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/module/{id}")]
        public async Task<DetailResponse<Module>> GetModuleByIdAsync(String id)
        {
            var module = await _moduleManager.GetModuleAsync(id, OrgEntityHeader, UserEntityHeader);
            var form = DetailResponse<Module>.Create(module);

            form.View[nameof(Module.UiCategory).CamelCase()].Options = new List<EnumDescription>( _moduleManager.GetTopLevelCategories().Select(cat=> 
            new EnumDescription() {  Id = cat.Id, Key = cat.Key, Label = cat.Name, Name = cat.Name, Help = cat.Summary, Text = cat.Name}));
            
            if (!IsPrimaryOrg)
                form.FormFields.Remove(nameof(Module.IsPublic));

            return form;
        }

        /// <summary>
        /// module - Get aras by id
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        [HttpGet("/api/module/{key}/my")]
        public async Task<Module> GetModuleByKeyAsync(String key)
        {
            var module = await _userAccessManager.GetUserModuleAsync(key, UserEntityHeader.Id, OrgEntityHeader.Id);
            return module;

        }

        /// <summary>
        /// module - Get aras by id
        /// </summary>
        /// <param name="key"></param>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpGet("/api/module/{key}/user/{userid}")]
        public async Task<Module> GetModuleByKeyForUserAsync(String key, string userid)
        {
            return await _userAccessManager.GetUserModuleAsync(key, userid, OrgEntityHeader.Id);
        }

        /// <summary>
        /// module - Get aras by key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        [HttpGet("/api/module/{key}/areas")]
        public async Task<IEnumerable<Area>> GetAreasAsync(String key)
        {
            var module = await _moduleManager.GetModuleByKeyAsync(key, OrgEntityHeader, UserEntityHeader);

            if(module == null)
            {
                throw new RecordNotFoundException(nameof(Module), key);
            }

            return module.Areas;
        }

        /// <summary>
        /// module - Get pages by key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="areakey"></param>
        /// <returns></returns>
        [HttpGet("/api/module/{key}/area/{areakey}/pages")]
        public async Task<IEnumerable<Page>> GetPagesAsync(String key, string areakey)
        {
            var module = await _moduleManager.GetModuleByKeyAsync(key, OrgEntityHeader, UserEntityHeader);

            if (module == null)
            {
                throw new RecordNotFoundException(nameof(Module), key);
            }

            var area = module.Areas.Single(ar=>ar.Key == areakey);
            if (area == null)
            {
                throw new RecordNotFoundException(nameof(Module), $"{key}-{areakey}");
            }

            return area.Pages;
        }

        [HttpGet("/api/module/moveup/{mod1id}/{mod2id}")]
        public async Task<InvokeResult> MoveModuleUp(string mod1id, string mod2id)
        {
            var mod1 = await _moduleManager.GetModuleAsync(mod1id, OrgEntityHeader, UserEntityHeader);
            var mod2 = await _moduleManager.GetModuleAsync(mod2id, OrgEntityHeader, UserEntityHeader);

            if (mod1.SortOrder != mod2.SortOrder)
            {
                var sort1 = mod1.SortOrder;
                mod1.SortOrder = mod2.SortOrder;
                mod2.SortOrder = sort1;
                SetUpdatedProperties(mod1);
                SetUpdatedProperties(mod2);
                await _moduleManager.UpdateModuleAsync(mod1, OrgEntityHeader, UserEntityHeader);
                await _moduleManager.UpdateModuleAsync(mod2, OrgEntityHeader, UserEntityHeader);
            }
            else
            {
                mod2.SortOrder--;
                SetUpdatedProperties(mod2);
                await _moduleManager.UpdateModuleAsync(mod2, OrgEntityHeader, UserEntityHeader);
            }

            return InvokeResult.Success;
        }


        [HttpGet("/api/module/movedown/{mod1id}/{mod2id}")]
        public async Task<InvokeResult> MoveModuleDown(string mod1id, string mod2id)
        {
            var mod1 = await _moduleManager.GetModuleAsync(mod1id, OrgEntityHeader, UserEntityHeader);
            var mod2 = await _moduleManager.GetModuleAsync(mod2id, OrgEntityHeader, UserEntityHeader);

            if (mod1.SortOrder != mod2.SortOrder)
            {
                var sort1 = mod1.SortOrder;
                mod1.SortOrder = mod2.SortOrder;
                mod2.SortOrder = sort1;
                SetUpdatedProperties(mod1);
                SetUpdatedProperties(mod2);
                await _moduleManager.UpdateModuleAsync(mod1, OrgEntityHeader, UserEntityHeader);
                await _moduleManager.UpdateModuleAsync(mod2, OrgEntityHeader, UserEntityHeader);
            }
            else
            {
                mod2.SortOrder++;
                SetUpdatedProperties(mod2);
                await _moduleManager.UpdateModuleAsync(mod2, OrgEntityHeader, UserEntityHeader);
            }

            return InvokeResult.Success;
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
            response.View[nameof(Module.UiCategory).CamelCase()].Options = new List<EnumDescription>(GetTopLevelCategories().Model.Select(opt=> 
                new EnumDescription() 
                {  Id = opt.Id, Key = opt.Key, Label = opt.Name, Name = opt.Name, Text = opt.Name}));
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);
            return response;
        }

        /// <summary>
        /// Ui Category - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/module/uicategory/factory")]
        public DetailResponse<UiCategory> CreateUiCategory()
        {
            return DetailResponse<UiCategory>.Create();
        }

        /// <summary>
        /// Ui Category - Get Top Level User Interface Categories
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/module/uicategories/top")]
        public ListResponse<UiCategory> GetTopLevelCategories()
        {
            return ListResponse<UiCategory>.Create(_moduleManager.GetTopLevelCategories());
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
