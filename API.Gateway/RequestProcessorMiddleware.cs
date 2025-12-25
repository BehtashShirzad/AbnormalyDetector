using System.Text.Json;
using API.Gateway.Events;
using API.Gateway.Services;
using Microsoft.Extensions.Caching.Memory;

namespace API.Gateway;

public static class SecurityConstants
{
    public const int MaxRequestsPerWindow = 20;
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(10);
}

public sealed class RequestProcessorMiddleware
{
 
    private const string DefaultServiceName = "API.Gateway";

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

 

    private static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(1);
    private const int MaxRequestsPerBurstWindow = 8;

    private static readonly TimeSpan ScanWindow = TimeSpan.FromSeconds(60);
    private const int MaxUniquePathsPerScanWindow = 25;

 
    private static readonly string[] SensitivePaths =
    {
    "/wp-admin", "/wp-login.php", "/.env", "/phpmyadmin", "/admin", "/login",
    "/actuator", "/metrics", "/swagger", "/graphql", "/robots.txt"
};

    public async Task InvokeAsync(HttpContext context)
    {
        var ip = GetClientIp(context);

        // 1) Rate & Burst
        await CheckRateAndBurstAsync(context, ip);

        // 2) Scan
        await CheckSuspiciousScanAsync(context, ip);

        // 3) Bot 
        await CheckBotDetectedAsync(context, ip);

        // 4) SQLi (Block)
        if (await DetectAndHandleSqlInjectionAsync(context, ip))
            return;

        // 5) XSS (Block)
        if (await DetectAndHandleXssAsync(context, ip))
            return;

        await _next(context);
    }


    private async Task CheckRateAndBurstAsync(HttpContext context, string ip)
    {
        // 10s window => RateLimiting
        var rateCount = IncrementCounter(ip, "RATE", SecurityConstants.Window);

        if (rateCount > SecurityConstants.MaxRequestsPerWindow)
        {
            await SafeRaiseEventAsync(CreateEvent(
                context, ip,
                SecurityEventType.RateLimiting,
                Severity.Warning,
                $"Rate limit exceeded: {rateCount} in {SecurityConstants.Window.TotalSeconds:0}s",
                statusCode: null,
                requestSnapshot: BuildSnapshot(context, new { rateCount, windowSec = SecurityConstants.Window.TotalSeconds })
            ));
        }

        // 1s window => Burst
        var burstCount = IncrementCounter(ip, "BURST", BurstWindow);

        if (burstCount > MaxRequestsPerBurstWindow)
        {
            await SafeRaiseEventAsync(CreateEvent(
                context, ip,
                SecurityEventType.TooManyRequestsBurst,
                Severity.Warning,
                $"Burst detected: {burstCount} in {BurstWindow.TotalSeconds:0}s",
                statusCode: null,
                requestSnapshot: BuildSnapshot(context, new { burstCount, windowSec = BurstWindow.TotalSeconds })
            ));
        }
    }

    private int IncrementCounter(string ip, string prefix, TimeSpan window)
    {
        var key = $"{prefix}_{ip}";
        var current = _cache.TryGetValue(key, out int v) ? v : 0;
        var next = current + 1;
        _cache.Set(key, next, window);
        return next;
    }


    private async Task CheckSuspiciousScanAsync(HttpContext context, string ip)
    {
        var path = context.Request.Path.ToString();

        // Sensitive path hit
        if (IsSensitivePath(path))
        {
            await SafeRaiseEventAsync(CreateEvent(
                context, ip,
                SecurityEventType.SuspiciousScan,
                Severity.Warning,
                $"Sensitive path probed: {path}",
                statusCode: null,
                requestSnapshot: BuildSnapshot(context, new { path })
            ));
            return;
        }

        // Unique paths in 60s
        var unique = TrackUniquePath(ip, path);

        if (unique >= MaxUniquePathsPerScanWindow)
        {
            await SafeRaiseEventAsync(CreateEvent(
                context, ip,
                SecurityEventType.SuspiciousScan,
                Severity.Warning,
                $"High unique path rate: {unique} unique paths in {ScanWindow.TotalSeconds:0}s",
                statusCode: null,
                requestSnapshot: BuildSnapshot(context, new { unique, windowSec = ScanWindow.TotalSeconds })
            ));
        }
    }

    private bool IsSensitivePath(string path)
    {
        foreach (var p in SensitivePaths)
        {
            if (path.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private int TrackUniquePath(string ip, string path)
    {
        var key = $"SCAN_{ip}";

    
        var set = _cache.GetOrCreate(key, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = ScanWindow;
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        });

        lock (set) 
        {
            set.Add(path);
            _cache.Set(key, set, ScanWindow);
            return set.Count;
        }
    }


    private async Task CheckBotDetectedAsync(HttpContext context, string ip)
    {
        var req = context.Request;

        var ua = GetUserAgent(req);
        var accept = req.Headers.Accept.ToString();
        var acceptLang = req.Headers.AcceptLanguage.ToString();

        int score = 0;

        if (string.IsNullOrWhiteSpace(ua)) score += 2;
        if (IsSuspiciousUserAgent(ua)) score += 3;
        if (string.IsNullOrWhiteSpace(accept)) score += 1;
        if (string.IsNullOrWhiteSpace(acceptLang)) score += 1;

        var burstCount = _cache.TryGetValue($"BURST_{ip}", out int b) ? b : 0;
        if (burstCount > MaxRequestsPerBurstWindow) score += 2;

        // scan behavior
        var scanSet = _cache.TryGetValue($"SCAN_{ip}", out HashSet<string>? s) ? s : null;
        var unique = scanSet?.Count ?? 0;
        if (unique >= MaxUniquePathsPerScanWindow) score += 2;

        if (score < 4) return;

        await SafeRaiseEventAsync(CreateEvent(
            context, ip,
            SecurityEventType.BotDetected,
            Severity.Warning,
            $"Bot-like behavior detected (score={score})",
            statusCode: null,
            requestSnapshot: BuildSnapshot(context, new { score, ua, accept, acceptLang, burstCount, uniquePaths = unique })
        ));
    }

    private static bool IsSuspiciousUserAgent(string ua)
    {
        ua = ua?.ToLowerInvariant() ?? "";
        return ua.Contains("curl")
            || ua.Contains("wget")
            || ua.Contains("python-requests")
            || ua.Contains("go-http-client")
            || ua.Contains("httpclient")
            || ua.Contains("scrapy");
    }

    private async Task<bool> DetectAndHandleXssAsync(HttpContext context, string ip)
    {
        var req = context.Request;

        if (req.Path.StartsWithSegments("/swagger", StringComparison.OrdinalIgnoreCase))
            return false;

        var routeValues = GetRouteValues(context);
        var queryValues = GetQueryValues(req);

        var combined = string.Join(" ", new[]
        {
        req.Path.ToString(),
        req.QueryString.ToString(),
        string.Join(" ", routeValues),
        string.Join(" ", queryValues)
    });

        if (!HasXssPayload(combined))
            return false;

        _logger.LogWarning("⚠️ Possible XSS detected | IP: {IP} | Path: {Path}", ip, req.Path.ToString());

        await SafeRaiseEventAsync(CreateEvent(
            context, ip,
            SecurityEventType.XSS,
            Severity.Attack,
            "Possible XSS payload detected",
            statusCode: StatusCodes.Status403Forbidden,
            requestSnapshot: BuildSnapshot(context, new { sample = Truncate(combined, 200) })
        ));

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentLength = 0;
        return true;
    }

    private static bool HasXssPayload(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;

         
        var decoded = Uri.UnescapeDataString(input).ToLowerInvariant();

      
        return decoded.Contains("<script")
            || decoded.Contains("javascript:")
            || decoded.Contains("onerror=")
            || decoded.Contains("onload=")
            || decoded.Contains("<svg")
            || decoded.Contains("<img")
            || decoded.Contains("data:text/html");
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s.Substring(0, max);

 
 

    // ============================
    // SQL Injection detection
    // ============================
    private async Task<bool> DetectAndHandleSqlInjectionAsync(HttpContext context, string ip)
    {
        var request = context.Request;

        
        if (request.Path.StartsWithSegments("/swagger", StringComparison.OrdinalIgnoreCase))
            return false;

        var routeValues = GetRouteValues(context);
        var queryValues = GetQueryValues(request);

        var result = SqlInjectionDetector.HasSqlInjection(
            request.Path,
            string.Join(" ", routeValues),
            string.Join(" ", queryValues)
        );

        if (!result.HasSqlInjection)
            return false;

        _logger.LogWarning(
            "⚠️ Possible SQL Injection detected | IP: {IP} | Path: {Path} | Query: {Query}",
            ip,
            request.Path.ToString(),
            request.QueryString.ToString()
        );

        var ev = CreateEvent(
            context: context,
            ip: ip,
            eventType: SecurityEventType.SQLInjection,
            severity: Severity.Attack,
            description: result.AnormalValue,
            statusCode: StatusCodes.Status403Forbidden,
            requestSnapshot: BuildSnapshot(context, new
            {
                abnormalValue = result.AnormalValue,
                routeValues,
                query = request.QueryString.ToString()
            })
        );

        await SafeRaiseEventAsync(ev);

        
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentLength = 0;
        return true;
    }

    // ============================
    // Event building / publishing
    // ============================
    private AnormalEvent CreateEvent(
        HttpContext context,
        string ip,
        SecurityEventType eventType,
        Severity severity,
        string description,
        int? statusCode,
        string? requestSnapshot)
    {
        var req = context.Request;

        return new AnormalEvent(
            Id: null,
            ServiceName: DefaultServiceName,
            Ip: ip,
            EventType: eventType,
            Severity: severity,
            Description: description,
            OccurredAt: DateTime.UtcNow,
            RequestId: GetRequestId(context),
            Method: req.Method,
            Path: req.Path.ToString(),
            StatusCode: statusCode,
            UserAgent: GetUserAgent(req),
            Request: requestSnapshot
        );
    }

    private async Task SafeRaiseEventAsync(AnormalEvent ev)
    {
        try
        {
            await _notifierClient.RaiseEvent(ev);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to publish security event to RabbitMQ. IP: {IP} Type: {Type}", ev.Ip, ev.EventType);
        }
    }

    private static string? BuildSnapshot(HttpContext context, object extra)
    {
        
        var req = context.Request;

        var payload = new
        {
            url = $"{req.Scheme}://{req.Host}{req.Path}{req.QueryString}",
            method = req.Method,
            path = req.Path.ToString(),
            query = req.QueryString.ToString(),
            ua = GetUserAgent(req),
            extra
        };

        return JsonSerializer.Serialize(payload);
    }

    // ============================
    // Helpers
    // ============================
    private static string GetClientIp(HttpContext context) =>
        context.Connection.RemoteIpAddress?.MapToIPv4().ToString()??"unknown";

    private static string? GetRequestId(HttpContext context) =>
        string.IsNullOrWhiteSpace(context.TraceIdentifier) ? null : context.TraceIdentifier;

    private static string GetUserAgent(HttpRequest request) =>
        request.Headers.UserAgent.ToString();

    private static string[] GetRouteValues(HttpContext context) =>
        context.Request.RouteValues
            .Select(rv => rv.Value?.ToString())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToArray();

    private static string[] GetQueryValues(HttpRequest request) =>
        request.Query.Select(q => q.Value.ToString()).ToArray();
}
