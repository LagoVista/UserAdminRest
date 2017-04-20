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

namespace LagoVista.UserAdmin.Rest
{
    [SystemAdmin]
    [Authorize]
    public class SubscriptionServices : LagoVistaBaseController
    {
        ISubscriptionManager _subscriptionManager;
        public SubscriptionServices(ISubscriptionManager appUserManager, UserManager<AppUser> userManager, ILogger logger) : base(userManager, logger)
        {
            _subscriptionManager = appUserManager;
        }


        private void SetAuditProperties(IAuditableEntity entity)
        {
            var createDate = DateTime.Now.ToJSONString();

            entity.CreationDate = createDate;
            entity.LastUpdatedDate = createDate;
            entity.CreatedBy = UserEntityHeader;
            entity.LastUpdatedBy = UserEntityHeader;
        }

        private void SetOwnedProperties(IOwnedEntity entity)
        {
            entity.OwnerOrganization = OrgEntityHeader;
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
        [HttpGet("/api/orgs/{subscriptionid}/subscriptions")]
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
        [HttpGet("/api/subscription/candelete/{id}")]
        public Task<bool> CanDeleteAsync(String id)
        {
            return _subscriptionManager.CanDeleteSubscriptionAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Subscription - Key In Use
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/subscription/keyinuse/{key}")]
        public Task<bool> HostKeyInUse(String key)
        {
            return _subscriptionManager.QueryKeyInUse(key, OrgEntityHeader);
        }

        /// <summary>
        /// Subscription - Delete
        /// </summary>
        /// <returns></returns>
        [HttpDelete("/api/subscription")]
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
