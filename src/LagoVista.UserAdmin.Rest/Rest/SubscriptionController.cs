using LagoVista.Core.Interfaces;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.PlatformSupport;
using LagoVista.Core.Validation;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Users;
using LagoVista.UserAdmin.Models.Orgs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using LagoVista.Core;
using System.Threading.Tasks;
using LagoVista.Core.Models;
using LagoVista.IoT.Logging.Loggers;

namespace LagoVista.UserAdmin.Rest
{
    [OrgAdmin]
    [Authorize]
    public class SubscriptionController : LagoVistaBaseController
    {
        ISubscriptionManager _subscriptionManager;
        public SubscriptionController(ISubscriptionManager appUserManager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _subscriptionManager = appUserManager;
        }

        /// <summary>
        /// Subscription - Add
        /// </summary>
        /// <param name="subscription"></param>
        /// <returns></returns>
        [HttpPost("/api/subscription")]
        public Task<InvokeResult> AddHostAsync([FromBody] SubscriptionDTO subscription)
        {
            return _subscriptionManager.AddSubscriptionAsync(subscription, UserEntityHeader, OrgEntityHeader);
        }

        /// <summary>
        /// Subscription - Update
        /// </summary>
        /// <param name="subscription"></param>
        /// <returns></returns>
        [HttpPut("/api/subscription")]
        public Task<InvokeResult> UpdateSubscriptionAsync([FromBody] SubscriptionDTO subscription)
        {
            subscription.LastUpdatedById = UserEntityHeader.Id;
            subscription.LastUpdatedDate = DateTime.UtcNow;
            return _subscriptionManager.UpdateSubscriptionAsync(subscription, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Subscription - Get
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/subscription/{id}")]
        public async Task<DetailResponse<SubscriptionDTO>> GetSubscriptionAsync(string id)
        {
            if (Guid.TryParse(id, out Guid subscrptionId))
            {
                var subscription = await _subscriptionManager.GetSubscriptionAsync(subscrptionId, OrgEntityHeader, UserEntityHeader);
                return DetailResponse<SubscriptionDTO>.Create(subscription);
            }
            else
            {
                throw new Exception("Must pass in subscription id must be a Guid.");
            }
        }


        /// <summary>
        /// Subscription - Get for Org
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/subscriptions")]
        public async Task<ListResponse<SubscriptionSummary>> GetSubscriptionsForOrgAsync()
        {
            var hostSummaries = await _subscriptionManager.GetSubscriptionsForOrgAsync(OrgEntityHeader.Id, UserEntityHeader);
            return ListResponse<SubscriptionSummary>.Create(hostSummaries);
        }


        /// <summary>
        /// Subscription - Key In Use
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/subscription/{key}/keyinuse")]
        public Task<bool> HostKeyInUse(String key)
        {
            return _subscriptionManager.QueryKeyInUseAsync(key, OrgEntityHeader);
        }


        /// <summary>
        /// Subscription - Get resources for subscription
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/subscription/{id}/resources")]
        public Task<ListResponse<SubscriptionResource>> GetSubscriptionResourcesAsync(string id)
        {
            if (Guid.TryParse(id, out Guid subscriptionId))
            {
                return _subscriptionManager.GetResourcesForSubscriptionAsync(subscriptionId, GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
            }
            else
            {
                throw new Exception("Must pass in subscription id must be a Guid.");
            }
        }

        /// <summary>
        ///  Subscription - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/subscription/factory")]
        public DetailResponse<SubscriptionDTO> CreateSubscriptionAsync()
        {
            var response = DetailResponse<SubscriptionDTO>.Create();
            response.Model.Id = Guid.NewGuid();
            response.Model.OrgId = OrgEntityHeader.Id;
            response.Model.Status = "active";
            response.Model.CreatedById = UserEntityHeader.Id;
            response.Model.CreationDate = DateTime.UtcNow;
            response.Model.LastUpdatedById = UserEntityHeader.Id;
            response.Model.LastUpdatedDate = response.Model.CreationDate;
            return response;
        }
    }
}
