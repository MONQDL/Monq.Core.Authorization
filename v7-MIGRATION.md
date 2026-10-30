# Migration to Monq.Core.Authorization 7.0.0

Version 7.0.0 removes the configuration-based (`BaseUri`) overloads of
`UseMonqAuthorization`. The user grants address is now resolved through
`Monq.Core.MicroserviceAddressing` by Kubernetes application name, or passed as an
explicit `Uri`.

The user grants API is hosted by the Work Groups service. There is no separate user
grants service, so the default application name is `pl-work-groups-api-service`
(`DependencyInjectionExtensions.DefaultUserGrantsApplicationName`).

## Breaking changes

- `UseMonqAuthorization(IConfiguration)` and
  `UseMonqAuthorization(MonqAuthorizationOptions, IConfiguration)` are removed.
- The `"BaseUri"` configuration key is no longer read anywhere.
- `MonqAuthorizationMiddleware` constructor no longer accepts `IConfiguration`
  (relevant only for manual middleware construction).
- A missing user grants address now throws `ArgumentException` instead of a generic
  `Exception`.

## Before (6.x)

```CSharp
// "BaseUri" was read from IConfiguration (appsettings, environment variables, Consul...).
app.UseMonqAuthorization(Configuration);

// or with options
app.UseMonqAuthorization(
    new MonqAuthorizationOptions { CacheTime = TimeSpan.FromSeconds(10) },
    Configuration);
```

## After (7.0)

In-cluster (Kubernetes), with an `IMicroserviceAddressProvider` registered (done by
`Monq.Core.BasicDotNetMicroservice` defaults):

```CSharp
// Resolves http://pl-work-groups-api-service via the application-wide HTTP resolver.
app.UseMonqAuthorization();

// or explicitly:
app.UseMonqAuthorization(DependencyInjectionExtensions.DefaultUserGrantsApplicationName);

// or with options:
app.UseMonqAuthorization(options: new MonqAuthorizationOptions
{
    CacheTime = TimeSpan.FromSeconds(10)
});
```

Another application hosting the user grants API:

```CSharp
app.UseMonqAuthorization("pl-work-groups-api-service", port: 8080);
```

Explicit address (a one-off case, or a non-cluster endpoint):

```CSharp
app.UseMonqAuthorization(new Uri("https://work-groups.example.test"));
```

Recommended pattern for local development outside Kubernetes — configure the resolver
once per environment so the parameterless call keeps working everywhere:

```CSharp
builder.Host.UseMicroserviceAddressResolver(context =>
    context.HostingEnvironment.IsDevelopment()
        ? new FixedMicroserviceAddressResolver(new Uri("https://work-groups.example.test"))
        : new KubernetesClusterIpAddressResolver());

...

app.UseMonqAuthorization();
```

Transition option — keep reading the old key yourself and pass it explicitly:

```CSharp
app.UseMonqAuthorization(new Uri(builder.Configuration["BaseUri"]!));
```

Note: with the default resolution the address is an in-cluster `http` ClusterIP address.
Outside Kubernetes (local development) the default overload cannot resolve the service;
pass an explicit `Uri` of your ingress/dev environment there.

The name-based overloads require `IMicroserviceAddressProvider` in the DI container.
Services based on `Monq.Core.BasicDotNetMicroservice` get it registered automatically;
custom hosts must call `builder.Host.UseMicroserviceAddressResolver(...)` or
`builder.Services.AddMicroserviceAddressing()`, otherwise
`UseMonqAuthorization()` fails to start with a descriptive DI error.

## Configuration cleanup

The root `"BaseUri"` key used by this library becomes dead configuration for services on
7.0.0. Remove it from Consul and application configuration after **all** consumers are
migrated. Be careful: `BaseUri` is a common key name — verify that no other component in
the same service reads it before deleting.
