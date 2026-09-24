using LagoVista.UserAdmin.Models.Security;
using System;
using System.Collections.Generic;
using System.Linq;

namespace LagoVista.UserAdmin.RouteReconciliation
{
    public class ModuleRouteReconciliationRequest
    {
        public List<ModuleRouteDescriptor> Routes { get; set; } = new List<ModuleRouteDescriptor>();
    }

    public class ModuleRouteDescriptor
    {
        public string Path { get; set; }
        public string Component { get; set; }
        public string RedirectTo { get; set; }
        public string PathMatch { get; set; }
    }

    public class ModuleRouteReconciliationResult
    {
        public string ModuleKey { get; set; }
        public string ModuleName { get; set; }
        public List<ModuleRouteReconciliationArea> Areas { get; set; } = new List<ModuleRouteReconciliationArea>();
        public List<ModuleRouteReconciliationItem> Items { get; set; } = new List<ModuleRouteReconciliationItem>();
        public List<ModuleRouteReconciliationOrphan> Orphaned { get; set; } = new List<ModuleRouteReconciliationOrphan>();
    }

    public class ModuleRouteReconciliationArea
    {
        public string Key { get; set; }
        public string Name { get; set; }
        public List<ModuleRouteReconciliationPage> Pages { get; set; } = new List<ModuleRouteReconciliationPage>();
    }

    public class ModuleRouteReconciliationPage
    {
        public string Key { get; set; }
        public string Name { get; set; }
    }

    public class ModuleRouteReconciliationItem
    {
        public string Path { get; set; }
        public string RelativePath { get; set; }
        public string Component { get; set; }
        public string Status { get; set; }
        public string ExistingAreaKey { get; set; }
        public string ExistingPageKey { get; set; }
        public string SuggestedPageKey { get; set; }
        public string RelatedPath { get; set; }
        public bool Parameterized { get; set; }
        public string Note { get; set; }
    }

    public class ModuleRouteReconciliationOrphan
    {
        public string Kind { get; set; }
        public string AreaKey { get; set; }
        public string PageKey { get; set; }
        public string Name { get; set; }
    }

    public static class ModuleRouteReconciler
    {
        public static ModuleRouteReconciliationResult Reconcile(Module module, ModuleRouteReconciliationRequest request)
        {
            var result = new ModuleRouteReconciliationResult
            {
                ModuleKey = module.Key,
                ModuleName = module.Name,
                Areas = module.Areas.Select(area => new ModuleRouteReconciliationArea
                {
                    Key = area.Key,
                    Name = area.Name,
                    Pages = area.Pages.Select(page => new ModuleRouteReconciliationPage
                    {
                        Key = page.Key,
                        Name = page.Name
                    }).ToList()
                }).ToList()
            };

            var moduleKey = Normalize(module.Key);
            var routes = (request?.Routes ?? new List<ModuleRouteDescriptor>())
                .Where(route => !String.IsNullOrWhiteSpace(route.Path))
                .Select(route => new
                {
                    Route = route,
                    Path = Normalize(route.Path)
                })
                .Where(route => route.Path.Equals(moduleKey, StringComparison.OrdinalIgnoreCase) || route.Path.StartsWith(moduleKey + "/", StringComparison.OrdinalIgnoreCase))
                .Where(route => String.IsNullOrWhiteSpace(route.Route.RedirectTo))
                .ToList();

            var navigableRoutes = routes
                .Where(route => !route.Path.Equals(moduleKey, StringComparison.OrdinalIgnoreCase))
                .Select(route => new
                {
                    route.Route,
                    route.Path,
                    RelativePath = route.Path.Substring(moduleKey.Length).Trim('/')
                })
                .Where(route => !String.IsNullOrWhiteSpace(route.RelativePath))
                .Where(route => !route.RelativePath.Equals("menueditor", StringComparison.OrdinalIgnoreCase))
                .Where(route => !route.RelativePath.Equals("areas/:area", StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var route in navigableRoutes)
            {
                var segments = route.RelativePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                var parameterized = segments.Any(segment => segment.StartsWith(":"));
                var staticSegments = segments.Where(segment => !segment.StartsWith(":"))
                    .ToArray();
                var suggestedKey = staticSegments.LastOrDefault();

                var item = new ModuleRouteReconciliationItem
                {
                    Path = route.Path,
                    RelativePath = route.RelativePath,
                    Component = route.Route.Component,
                    Parameterized = parameterized,
                    SuggestedPageKey = suggestedKey,
                    Status = "missing"
                };

                var area = module.Areas.FirstOrDefault(candidate =>
                    candidate.Key.Equals(route.RelativePath, StringComparison.OrdinalIgnoreCase) ||
                    candidate.Key.Equals(suggestedKey, StringComparison.OrdinalIgnoreCase));

                if (area != null && area.Pages.Count == 0)
                {
                    item.Status = "matched";
                    item.ExistingAreaKey = area.Key;
                    item.Note = "Matches a module-level destination.";
                }
                else
                {
                    var pageMatch = module.Areas
                        .SelectMany(candidate => candidate.Pages.Select(page => new { Area = candidate, Page = page }))
                        .FirstOrDefault(candidate =>
                            candidate.Page.Key.Equals(route.RelativePath, StringComparison.OrdinalIgnoreCase) ||
                            candidate.Page.Key.Equals(suggestedKey, StringComparison.OrdinalIgnoreCase) ||
                            ($"{candidate.Area.Key}/{candidate.Page.Key}").Equals(route.RelativePath, StringComparison.OrdinalIgnoreCase));

                    if (pageMatch != null)
                    {
                        item.Status = "matched";
                        item.ExistingAreaKey = pageMatch.Area.Key;
                        item.ExistingPageKey = pageMatch.Page.Key;
                        item.Note = "Matches an existing page.";
                    }
                }

                if (item.Status == "missing" && parameterized)
                {
                    item.Status = "supporting";
                    item.Note = "Parameterized/detail route. Only static routes participate in the Module / Area / Page menu hierarchy.";
                }

                result.Items.Add(item);
            }

            var matchedAreas = result.Items.Where(item => item.Status == "matched" && !String.IsNullOrWhiteSpace(item.ExistingAreaKey))
                .Select(item => item.ExistingAreaKey)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var matchedPages = result.Items.Where(item => item.Status == "matched" && !String.IsNullOrWhiteSpace(item.ExistingPageKey))
                .Select(item => $"{item.ExistingAreaKey}/{item.ExistingPageKey}")
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var area in module.Areas)
            {
                if (area.Pages.Count == 0)
                {
                    if (!matchedAreas.Contains(area.Key))
                    {
                        result.Orphaned.Add(new ModuleRouteReconciliationOrphan
                        {
                            Kind = "destination",
                            AreaKey = area.Key,
                            Name = area.Name
                        });
                    }
                    continue;
                }

                foreach (var page in area.Pages)
                {
                    if (!matchedPages.Contains($"{area.Key}/{page.Key}"))
                    {
                        result.Orphaned.Add(new ModuleRouteReconciliationOrphan
                        {
                            Kind = "page",
                            AreaKey = area.Key,
                            PageKey = page.Key,
                            Name = page.Name
                        });
                    }
                }
            }

            return result;
        }

        private static string Normalize(string path)
        {
            return (path ?? String.Empty).Trim().Trim('/');
        }
    }
}
