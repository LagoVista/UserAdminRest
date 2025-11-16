// --- BEGIN CODE INDEX META (do not edit) ---
// ContentHash: 1642c33ef669675c1a8d49e22c0301b01baecab56a7a1a11ef720d3e746f5634
// IndexVersion: 2
// --- END CODE INDEX META ---
using LagoVista.Core.Models.UIMetaData;
using LagoVista.Core.Validation;
using LagoVista.IoT.Logging.Loggers;
using LagoVista.IoT.Web.Common.Controllers;
using LagoVista.UserAdmin.Interfaces.Managers;
using LagoVista.UserAdmin.Models.Calendar;
using LagoVista.UserAdmin.Models.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace LagoVista.UserAdmin.Rest
{

    [Authorize]
    public class CalendarController : LagoVistaBaseController
    {
        ICalendarManager _manager;

        public CalendarController(ICalendarManager manager, UserManager<AppUser> userManager, IAdminLogger logger) : base(userManager, logger)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
        }


        /// <summary>
        /// Calendar Event - Add
        /// </summary>
        /// <param name="calendarEvent"></param>
        [HttpPost("/api/calendar/event")]
        public Task<InvokeResult<CalendarEvent>> AddCalendarEventAsync([FromBody] CalendarEvent calendarEvent)
        {
            return _manager.AddCalendarEventAsync(calendarEvent, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Calendar Event - Add
        /// </summary>
        /// <param name="calendarEvent"></param>
        [HttpPut("/api/calendar/event")]
        public Task<InvokeResult<CalendarEvent>> UpdateModuleListAsync([FromBody] CalendarEvent calendarEvent)
        {
            SetUpdatedProperties(calendarEvent);
            return _manager.UpdateCalendarEventAsync(calendarEvent, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Calendar - Get for month
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/calendar/month/{year}/{month}")]
        public Task<ListResponse<CalendarEventSummary>> GetEventsForMonth(int year, int month)
        {
            return _manager.GetEventsForMonthAsync(year, month, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Calendar - Get for day
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/calendar/day/{year}/{month}/{day}")]
        public Task<ListResponse<CalendarEventSummary>> GetEventsForDay(int year, int month, int day)
        {
            return _manager.GetEventsForDayAsync(year, month, day, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Calendar - Get for week
        /// </summary>
        /// <returns></returns>
        [HttpGet("/api/calendar/week/{year}/{month}/{day}")]
        public Task<ListResponse<CalendarEventSummary>> GetEventsForWeek(int year, int month, int day)
        {
            return _manager.GetEventsForWeekAsync(year, month, day, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Calendar Event - Get
        /// </summary>
        [HttpGet("/api/calendar/event/{id}")]
        public async Task<DetailResponse<CalendarEvent>> GetEvent(string id)
        {
            var calendarEvent = await _manager.GetCalendarEventAsync(id, OrgEntityHeader, UserEntityHeader);
            return DetailResponse<CalendarEvent>.Create(calendarEvent);
        }

        /// <summary>
        /// Calendar Event - Delete
        /// </summary>
        [HttpDelete("/api/calendar/event/{id}")]
        public async Task<InvokeResult> DeleteEvent(string id)
        {
            return await _manager.DeleteCalendarEventAsync(id, OrgEntityHeader, UserEntityHeader);
        }

        /// <summary>
        /// Calendar Event - Create
        /// </summary>
        [HttpGet("/api/calendar/event/factory")]
        public DetailResponse<CalendarEvent> Factory(string id)
        {
            var calendarEvent = new CalendarEvent();
            SetAuditProperties(calendarEvent);
            SetOwnedProperties(calendarEvent);
            return DetailResponse<CalendarEvent>.Create(calendarEvent);
        }

    }
}