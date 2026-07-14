namespace WebApplicationNativeAot.Configuration;

public static class AuthConstants
{
    internal static class AuthenticationConfiguration
    {
        public const string Authority = "AuthenticationEndpoint";
        public const string ScopeName = "ApiResource:Login";
        public const string ScopeSecret = "ApiResource:Password";

        public const string RequireHttpsMetadata = "RequireHttpsMetadata";
        public const string EnableCaching = "EnableCaching";
    }
}
