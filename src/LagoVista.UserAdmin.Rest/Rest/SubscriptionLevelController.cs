using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Orgs;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    [SystemAdmin]
    [Authorize]
    public class SubscriptionLevelController : LagoVistaBaseController
    {
        private readonly ISubscriptionLevelManager _subscriptionLevelManager;

        public SubscriptionLevelController(ISubscriptionLevelManager subscriptionLevelManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _subscriptionLevelManager = subscriptionLevelManager ?? throw new ArgumentNullException(nameof(subscriptionLevelManager));
        }

        /// <summary>
        /// Subscription Level - Add
        /// </summary>
        /// <param name="subscriptionLevel"></param>
        /// <returns></returns>
        [HttpPost("/api/sys/subscriptionlevel")]
        public Task<InvokeResult> AddSubscriptionLevelAsync([FromBody] SubscriptionLevel subscriptionLevel)
        {
            return _subscriptionLevelManager.AddSubscriptionLevelAsync(subscriptionLevel);
        }

        /// <summary>
        /// Subscription Level - Update
        /// </summary>
        /// <param name="subscriptionLevel"></param>
        /// <returns></returns>
        [HttpPut("/api/sys/subscriptionlevel")]
        public Task<InvokeResult> UpdateSubscriptionLevelAsync([FromBody] SubscriptionLevel subscriptionLevel)
        {
            return _subscriptionLevelManager.UpdateSubscriptionLevelAsync(subscriptionLevel);
        }

        /// <summary>
        /// Subscription Level - Delete
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpDelete("/api/sys/subscriptionlevel/{id}")]
        public Task<InvokeResult> DeleteSubscriptionLevelAsync(Guid id)
        {
            return _subscriptionLevelManager.DeleteSubscriptionLevelAsync(id);
        }

        /// <summary>
        /// Subscription Level - Get by Id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/subscriptionlevel/{id}")]
        public async Task<DetailResponse<SubscriptionLevel>> GetSubscriptionLevelAsync(Guid id)
        {
            var subscriptionLevel = await _subscriptionLevelManager.GetSubscriptionLevelAsync(id);
            return DetailResponse<SubscriptionLevel>.Create(subscriptionLevel);
        }

        /// <summary>
        /// Subscription Level - Get by Key
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/subscriptionlevel/key/{key}")]
        public async Task<DetailResponse<SubscriptionLevel>> GetSubscriptionLevelByKeyAsync(string key)
        {
            var subscriptionLevel = await _subscriptionLevelManager.GetSubscriptionLevelByKeyAsync(key);
            return DetailResponse<SubscriptionLevel>.Create(subscriptionLevel);
        }

        /// <summary>
        /// Subscription Levels - List
        /// </summary>
        /// <param name="activeOnly"></param>
        /// <returns></returns>
        [HttpGet("/api/sys/subscriptionlevels")]
        public Task<List<SubscriptionLevel>> GetSubscriptionLevelsAsync([FromQuery] bool activeOnly = false)
        {
            return _subscriptionLevelManager.GetSubscriptionLevelsAsync(activeOnly);
        }

        /// <summary>
        /// Subscription Level - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/sys/subscriptionlevel/factory")]
        public DetailResponse<SubscriptionLevel> CreateSubscriptionLevel()
        {
            return DetailResponse<SubscriptionLevel>.Create(new SubscriptionLevel { Id = Guid.NewGuid(), IsActive = true });
        }
    }
}
