using Consul;
using Yarp.ReverseProxy.Configuration;
using DestinationConfig = Yarp.ReverseProxy.Configuration.DestinationConfig;
using RouteConfig = Yarp.ReverseProxy.Configuration.RouteConfig;

namespace API.Gateway
{
    public class ConsulYarpUpdater : BackgroundService
    {
        private readonly IConsulClient _consul;
        private readonly InMemoryConfigProvider _configProvider;
        private readonly ILogger<ConsulYarpUpdater> _logger;

        public ConsulYarpUpdater(IConsulClient consul, IProxyConfigProvider provider, ILogger<ConsulYarpUpdater> logger)
        {
            _consul = consul;
            _configProvider = (InMemoryConfigProvider)provider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var services = await _consul.Agent.Services(stoppingToken);

                    // 🔹 کلید: از Distinct برای حذف تکراری‌ها استفاده کن
                    var uniqueServices = services.Response.Values
                        .GroupBy(s => s.Service)
                        .Select(g => g.First())
                        .ToList();

                    var clusters = new List<ClusterConfig>();
                    var routes = new List<RouteConfig>();

                    foreach (var service in uniqueServices)
                    {
                        var clusterId = service.Service;

                        var destination = new DestinationConfig
                        {
                            Address = $"https://{service.Address}:{service.Port}"
                        };

                        clusters.Add(new ClusterConfig
                        {
                            ClusterId = clusterId,
                            Destinations = new Dictionary<string, DestinationConfig>
                            {
                                { $"{clusterId}-dest", destination }
                            }
                        });

                        routes.Add(new RouteConfig
                        {
                            RouteId = $"{clusterId}-route",
                            ClusterId = clusterId,
                            Match = new RouteMatch { Path = $"/{clusterId}/{{**catch-all}}" },
                            Transforms = new[]
         {
        new Dictionary<string, string>
        {
            { "PathRemovePrefix", $"/{clusterId}" }
        }
    }
                        });

                    }

                    _configProvider.Update(routes, clusters);

                    _logger.LogInformation("✅ Updated {count} services from Consul.", routes.Count);
                    foreach (var route in routes)
                        _logger.LogInformation($"Route: {route.Match.Path}");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to update YARP config from Consul.");
                }

                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }
}
