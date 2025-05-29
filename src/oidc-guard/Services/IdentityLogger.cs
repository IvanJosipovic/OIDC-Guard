using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;

namespace oidc_guard.Services;

public class IdentityLogger : IIdentityLogger
{
    private readonly ILogger<IdentityLogger> logger;

    public IdentityLogger(ILogger<IdentityLogger> logger)
    {
        this.logger = logger;
    }

    public bool IsEnabled(EventLogLevel eventLogLevel)
    {
        return logger.IsEnabled(GetLogLevel(eventLogLevel));
    }

    public void Log(LogEntry entry)
    {
        logger.Log(GetLogLevel(entry.EventLogLevel), entry.Message, entry.CorrelationId);
    }

    private static LogLevel GetLogLevel(EventLogLevel eventLogLevel)
    {
        return eventLogLevel switch
        {
            EventLogLevel.LogAlways => LogLevel.Trace,
            EventLogLevel.Critical => LogLevel.Critical,
            EventLogLevel.Error => LogLevel.Error,
            EventLogLevel.Warning => LogLevel.Warning,
            EventLogLevel.Informational => LogLevel.Information,
            EventLogLevel.Verbose => LogLevel.Debug,
            _ => LogLevel.None
        };
    }
}
