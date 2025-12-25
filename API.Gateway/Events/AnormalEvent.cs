namespace API.Gateway.Events;

public sealed record AnormalEvent(
    long? Id,
    string ServiceName,
    string Ip,
    SecurityEventType EventType,
    Severity Severity,             // ✅ به جای short
    string Description,
    DateTime OccurredAt,
    string? RequestId = null,
    string? Method = null,
    string? Path = null,
    int? StatusCode = null,
    string? UserAgent = null,
    string? Request = null
);

public enum Severity : short
{
    Info = 0,
    Warning = 1,
    Error = 2,
    Attack = 3
}

public enum SecurityEventType : int
{
    Unknown = 0,
    SQLInjection = 1,
    XSS = 2,

    RateLimiting = 10,
    TooManyRequestsBurst = 11,
    SuspiciousScan = 12,
    BotDetected = 13,

    WafRuleTriggered = 20,
    FirewallBlock = 21
}
