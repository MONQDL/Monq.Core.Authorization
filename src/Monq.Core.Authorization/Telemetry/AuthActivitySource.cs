using System.Diagnostics;

namespace Monq.Core.Authorization.Telemetry;

/// <summary>
/// ActivitySource для трассировки операций авторизации Monq.Core.Authorization.
/// </summary>
public sealed class AuthActivitySource
{
    /// <summary>
    /// Имя источника активности для регистрации в OpenTelemetry.
    /// </summary>
    public const string SourceName = "Monq.Core.Authorization";

    /// <summary>
    /// Экземпляр ActivitySource для создания активностей.
    /// </summary>
    public static readonly ActivitySource Source = new(SourceName);
}
