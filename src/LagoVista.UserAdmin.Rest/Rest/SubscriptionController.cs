// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: 61b8868173d0b6da1b718c5dc8c3413b1b5af26d7e12f00787254d3525ac33c5
// IndexVersion: 2
// --- END CODE INDEX META ---
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
        public Task<InvokeResult> AddHostAsync([FromBody] Subscription subscription)
        {
            return _subscriptionManager.AddSubscriptionAsync(subscription, UserEntityHeader, OrgEntityHeader);
        }

        /// <summary>
        /// Subscription - Update
        /// </summary>
        /// <param name="subscription"></param>
        /// <returns></returns>
        [HttpPut("/api/subscription")]
        public Task<InvokeResult> UpdateSubscriptionAsync([FromBody] Subscription subscription)
        {
            SetUpdatedProperties(subscription);
            return _subscriptionManager.UpdateSubscriptionAsync(subscription, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Subscription - Get
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/subscription/{id}")]
        public async Task<DetailResponse<Subscription>> GetSubscriptionAsync(string id)
        {
            if (Guid.TryParse(id, out Guid subscrptionId))
            {
                var subscription = await _subscriptionManager.GetSubscriptionAsync(subscrptionId, OrgEntityHeader, UserEntityHeader);
                return DetailResponse<Subscription>.Create(subscription);
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
        public Task<ListResponse<SubscriptionSummary>> GetSubscriptionsForOrgAsync()
        {
            return _subscriptionManager.GetSubscriptionsForOrgAsync(GetListRequestFromHeader(), OrgEntityHeader, UserEntityHeader);
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
        public DetailResponse<Subscription> CreateSubscriptionAsync()
        {
            var response = DetailResponse<Subscription>.Create();
            SetOwnedProperties(response.Model);
            SetAuditProperties(response.Model);
            return response;
        }
    }
}
