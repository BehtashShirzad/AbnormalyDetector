 
using API.Gateway.Services;
using Microsoft.Extensions.Caching.Memory;

namespace API.Gateway;
public static class SecurityConstants
{
    public const int MaxRequestsPerWindow = 20;
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(10);
}


public class RequestProcessorMiddleware
{
    private readonly RequestDelegate _next;
    private readonly RabbitMqClient _notifierClient;
    private readonly ILogger<RequestProcessorMiddleware> _logger;
    private readonly IMemoryCache _cache;

    public RequestProcessorMiddleware(
        RequestDelegate next,
        ILogger<RequestProcessorMiddleware> logger,
        RabbitMqClient notifierClient,
        IMemoryCache memoryCache)
    {
        _next = next;
        _logger = logger;
        _notifierClient = notifierClient;
        _cache = memoryCache;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var ip = GetClientIp(context);

        await CheckRateLimitAsync(ip);

        if (await DetectAndHandleSqlInjectionAsync(context))
            return;  

        await _next(context);
    }

    // ============================
    // Rate limiting
    // ============================
    private async Task CheckRateLimitAsync(string ip)
    {
        var cacheKey = $"REQ_RATE_{ip}";

        var counter = _cache.GetOrCreate(cacheKey, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = SecurityConstants.Window;
            return 0;
        });

        counter++;
        _cache.Set(cacheKey, counter, SecurityConstants.Window);

        if (counter <= SecurityConstants.MaxRequestsPerWindow)
            return;

        _logger.LogWarning(
            "⚠️ High request rate detected | IP: {IP} | Count: {Count}",
            ip,
            counter);

        await _notifierClient.RaiseEvent(new(
            ip,
            $"Rate limit exceeded: {counter} requests in {SecurityConstants.Window.TotalSeconds}s",
            Events.Severity.Warning,
            DateTime.UtcNow));
    }

    // ============================
    // SQL Injection detection
    // ============================
    private async Task<bool> DetectAndHandleSqlInjectionAsync(HttpContext context)
    {
        var request = context.Request;

        var routeValues = GetRouteValues(context);
        var fullUrl =
    $"{request.Scheme}://{request.Host}{request.Path}{request.QueryString}";
        if (request.Path.Value.Contains("swagger"))
            return false;
        var queryValues = GetQueryValues(request);


        var result = SqlInjectionDetector.HasSqlInjection(
            request.Path,
            string.Join(" ", routeValues),
            string.Join(" ", queryValues)
        );

        if (!result.HasSqlInjection)
            return false;

        _logger.LogWarning(
            "⚠️ Possible SQL Injection detected | IP: {IP} | Path: {Path} | Route: {Route} | Query: {Query}",
            GetClientIp(context),
            request.Path.ToString(),
            context.Request.RouteValues,
            request.QueryString.ToString());

        await _notifierClient.RaiseEvent(new(
           fullUrl,
            result.AnormalValue,
            Events.Severity.Attack,
            DateTime.UtcNow));

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentLength = 0;

        return true; // ⛔ request متوقف شد
    }

    // ============================
    // Helpers
    // ============================
    private static string GetClientIp(HttpContext context) =>
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private static string[] GetRouteValues(HttpContext context) =>
        context.Request.RouteValues
            .Select(rv => rv.Value?.ToString())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToArray();

    private static string[] GetQueryValues(HttpRequest request) =>
        request.Query
            .Select(q => q.Value.ToString())
            .ToArray();
 
}