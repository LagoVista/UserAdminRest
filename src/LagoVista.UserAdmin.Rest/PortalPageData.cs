using LagoVista.Core.Models;
using LagoVista.ProjectManagement.Models;
using LagoVista.UserAdmin.Models.Auth;
using LagoVista.UserAdmin.Models.Security;
using LagoVista.UserAdmin.Models.Users;
using System.Collections.Generic;
using System.Diagnostics;

namespace LagoVista.UserAdmin
{
    public class PortalPageData : UserLoginResponse
    {
        private Stopwatch _sw;

        public PortalPageData(UserLoginResponse response)
        {
            User = response.User;
            MostRecentlyUsed = response.MostRecentlyUsed;
            Favorites = response.Favorites;
            Id = response.Id;
            Key = response.Key;
            Text = response.Text;
            Metrics.AddRange(response.AuthMetrics);
            _sw = Stopwatch.StartNew();
        }

        public List<ModuleSummary> Modules { get; set; }
        public Module Module { get; set; }

        public int InboxCount { get; set; }

        public List<EntityHeader> ActiveProjects { get; set; }
        public List<EntityHeader> ActiveUsers { get; set; }


        public List<MileStoneSummary> Milestones { get; set; }
        public List<ToDoSummary> ToDos { get; set; }

        public string InboxWebSocketUrl { get; set; }
        public string ToDoWebSocketUrl { get; set; }

        public List<Metric> Metrics { get; } = new List<Metric>();

        public void AddMetric(string name)
        {
            Metrics.Add(new Metric(name, _sw.ElapsedMilliseconds));
            _sw = Stopwatch.StartNew();
        }

        public double ServerLoadTime { get; set; }


    }
}
