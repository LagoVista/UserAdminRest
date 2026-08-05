using LagoVista.Core.Models;
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Attributes;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Managers;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.UserAdmin.Models.DTOs;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{
    /// <summary>
    /// Allows tenant administrators to manage AppEndUser accounts associated with a customer.
    /// </summary>
    [Authorize]
    public class CustomerUserController : LagoVistaBaseController
    {
        private readonly ICustomerUserManager _customerUserManager;

        public CustomerUserController(ICustomerUserManager customerUserManager, UserManager<AppUser> userManager, IAdminLogger adminLogger) : base(userManager, adminLogger)
        {
            _customerUserManager = customerUserManager ?? throw new ArgumentNullException(nameof(customerUserManager));
        }

        /// <summary>
        /// Returns all AppEndUser accounts associated with a customer in the current tenant.
        /// </summary>
        [OrgAdmin]
        [HttpGet("/api/customer/{customerId}/users")]
        public Task<ListResponse<UserInfoSummary>> GetCustomerUsersAsync(string customerId)
        {
            return _customerUserManager.GetCustomerUsersAsync(
                CreateCustomerHeader(customerId),
                OrgEntityHeader,
                UserEntityHeader,
                GetListRequestFromHeader());
        }

        /// <summary>
        /// Returns one AppEndUser account associated with a customer in the current tenant.
        /// </summary>
        [OrgAdmin]
        [HttpGet("/api/customer/{customerId}/user/{userId}")]
        public async Task<DetailResponse<CustomerUserSummary>> GetCustomerUserAsync(string customerId, string userId)
        {
            var result = await _customerUserManager.GetCustomerUserAsync(
                userId,
                CreateCustomerHeader(customerId),
                OrgEntityHeader,
                UserEntityHeader);


            return DetailResponse<CustomerUserSummary>.Create(result.Result);
        }

        /// <summary>
        /// Creates an AppEndUser account for an existing customer in the current tenant.
        /// </summary>
        [OrgAdmin]
        [HttpPost("/api/customer/{customerId}/user")]
        public Task<InvokeResult<CreateUserResponse>> CreateCustomerUserAsync(string customerId, [FromBody] CreateCustomerUserRequest request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            var customer = CreateCustomerHeader(customerId, request.Customer?.Text);

            request.Customer = customer;
            request.EndUserAppOrg = OrgEntityHeader;
            request.AutoLogin = false;

            return _customerUserManager.CreateCustomerUserAsync(
                request,
                customer,
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Updates the tenant-manageable fields of an AppEndUser account.
        /// </summary>
        [OrgAdmin]
        [HttpPut("/api/customer/{customerId}/user/{userId}")]
        public Task<InvokeResult<CustomerUserSummary>> UpdateCustomerUserAsync(string customerId, string userId, [FromBody] UpdateCustomerUserRequest request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            if (EntityHeader.IsNullOrEmpty(request.CustomerContact))
                return Task.FromResult(InvokeResult<CustomerUserSummary>.FromError("CustomerContact is required."));

            return _customerUserManager.UpdateCustomerUserAsync(
                userId,
                request,
                CreateCustomerHeader(customerId),
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Enables an AppEndUser account.
        /// </summary>
        [OrgAdmin]
        [HttpPost("/api/customer/{customerId}/user/{userId}/enable")]
        public Task<InvokeResult> EnableCustomerUserAsync(string customerId, string userId)
        {
            return _customerUserManager.EnableCustomerUserAsync(
                userId,
                CreateCustomerHeader(customerId),
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Disables an AppEndUser account.
        /// </summary>
        [OrgAdmin]
        [HttpPost("/api/customer/{customerId}/user/{userId}/disable")]
        public Task<InvokeResult> DisableCustomerUserAsync(string customerId, string userId)
        {
            return _customerUserManager.DisableCustomerUserAsync(
                userId,
                CreateCustomerHeader(customerId),
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Grants customer-administrator privileges to an AppEndUser account.
        /// </summary>
        [OrgAdmin]
        [HttpPost("/api/customer/{customerId}/user/{userId}/customer-admin")]
        public Task<InvokeResult> SetCustomerAdminAsync(string customerId, string userId)
        {
            return _customerUserManager.SetCustomerAdminAsync(
                userId,
                CreateCustomerHeader(customerId),
                OrgEntityHeader,
                UserEntityHeader);
        }

        /// <summary>
        /// Revokes customer-administrator privileges from an AppEndUser account.
        /// </summary>
        [OrgAdmin]
        [HttpDelete("/api/customer/{customerId}/user/{userId}/customer-admin")]
        public Task<InvokeResult> ClearCustomerAdminAsync(string customerId, string userId)
        {
            return _customerUserManager.ClearCustomerAdminAsync(
                userId,
                CreateCustomerHeader(customerId),
                OrgEntityHeader,
                UserEntityHeader);
        }

        private static EntityHeader CreateCustomerHeader(string customerId, string customerName = null)
        {
            if (String.IsNullOrWhiteSpace(customerId))
                throw new ArgumentNullException(nameof(customerId));

            return new EntityHeader
            {
                Id = customerId,
                Text = String.IsNullOrWhiteSpace(customerName) ? customerId : customerName
            };
        }
    }
}