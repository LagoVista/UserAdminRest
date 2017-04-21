using LagoVista.Core.Interfaces;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.PlatformSupport;
using LagoVista.Core.Validation;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Account;
using LagoVista.UserAdmin.Models.Orgs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using LagoVista.Core;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using LagoVista.Core.Models;

namespace LagoVista.UserAdmin.Rest
{
    [SystemAdmin]
    [Authorize]
    public class SubscriptionController : LagoVistaBaseController
    {
        ISubscriptionManager _subscriptionManager;
        public SubscriptionController(ISubscriptionManager appUserManager, UserManager<AppUser> userManager, ILogger logger) : base(userManager, logger)
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
            var subscription = await _subscriptionManager.GetSubscriptionAsync(id, OrgEntityHeader, UserEntityHeader);

            return DetailResponse<Subscription>.Create(subscription);
        }


        /// <summary>
        /// Subscription - Get for Org
        /// </summary>
        /// <param name="orgId">Organization Id</param>
        /// <returns></returns>
        [HttpGet("/api/org/{orgid}/subscriptions")]
        public async Task<ListResponse<SubscriptionSummary>> GetSubscriptionsForOrgAsync(String orgId)
        {
            var hostSummaries = await _subscriptionManager.GetSubscriptionsForOrgAsync(orgId, UserEntityHeader);
            var response = ListResponse<SubscriptionSummary>.Create(hostSummaries);

            return response;
        }

        /// <summary>
        /// Subscription - Can Delete
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("/api/subscription/{id}/inuse")]
        public Task<DependentObjectCheckResult> CheckInUse(String id)
        {
            return _subscriptionManager.CheckInUseAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Subscription - Key In Use
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/subscription/{key}/keyinuse")]
        public Task<bool> HostKeyInUse(String key)
        {
            return _subscriptionManager.QueryKeyInUse(key, OrgEntityHeader);
        }

        /// <summary>
        /// Subscription - Delete
        /// </summary>
        /// <returns></returns>
        [HttpDelete("/api/subscription/{id}")]
        public Task<InvokeResult> DeleteSubscriptionAsync(string id)
        {
            return _subscriptionManager.DeleteSubscriptionAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        ///  Subscription - Create New
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/subscription/factory")]
        public DetailResponse<Subscription> CreateSubscriptionAsync()
        {
            var response = DetailResponse<Subscription>.Create();
            response.Model.Id = Guid.NewGuid().ToId();
            SetAuditProperties(response.Model);
            SetOwnedProperties(response.Model);

            return response;
        }
    }
}
