using System.Diagnostics;

namespace Monq.Core.Authorization.Telemetry;

/// <summary>
/// ActivitySource for tracing Monq.Core.Authorization authorization operations.
/// </summary>
public sealed class AuthActivitySource
{
    /// <summary>
    /// The activity source name for registration in OpenTelemetry.
    /// </summary>
    public const string SourceName = "Monq.Core.Authorization";

    /// <summary>
    /// The ActivitySource instance used to create activities.
    /// </summary>
    public static readonly ActivitySource Source = new(SourceName);
}
