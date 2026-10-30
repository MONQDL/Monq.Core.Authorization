# monq-core-authorization

The library is a wrapper for the methods that request user permissions from the authorization
(user grants) service and apply them to the request `ClaimsPrincipal`.

The user grants API is hosted by the Work Groups service (`pl-work-groups-api-service`);
there is no separate user grants service anymore. Since version 7.0.0 the library resolves
its address through [Monq.Core.MicroserviceAddressing](https://www.nuget.org/packages/Monq.Core.MicroserviceAddressing)
by application name, like the other Monq libraries.

<!-- TOC depthFrom:2 -->

- [monq-core-authorization](#monq-core-authorization)
  - [Installation](#installation)
  - [Connection](#connection)
    - [Options](#options)
  - [Migration to 7.0.0](#migration-to-700)
  - [OpenTelemetry](#opentelemetry)
    - [Connection](#connection-1)
    - [Produced spans](#produced-spans)
    - [Tags](#tags)
  - [Extension methods](#extension-methods)
    - [Subject()](#subject)
    - [Userspace()](#userspace)
    - [Packets()](#packets)
    - [IsSystemUser()](#issystemuser)
    - [IsWorkGroupManager(long userspaceId, long workGroupId)](#isworkgroupmanagerlong-userspaceid-long-workgroupid)
    - [HasGrant(long userspaceId, long workGroupId, string grantName)](#hasgrantlong-userspaceid-long-workgroupid-string-grantname)
    - [HasAnyGrant(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)](#hasanygrantlong-userspaceid-long-workgroupid-ienumerableltstringgt-grantnames)
    - [HasAllGrants(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)](#hasallgrantslong-userspaceid-long-workgroupid-ienumerableltstringgt-grantnames)
    - [HasUserspaceAdminPanelGrant(long userspaceId, string adminPanelGrant)](#hasuserspaceadminpanelgrantlong-userspaceid-string-adminpanelgrant)
    - [HasAnyUserspaceAdminPanelGrant(long userspaceId, IEnumerable&lt;string&gt; adminPanelGrantNames)](#hasanyuserspaceadminpanelgrantlong-userspaceid-ienumerableltstringgt-adminpanelgrantnames)
    - [GetWorkGroupsWithGrant(long userspaceId, string grantName)](#getworkgroupswithgrantlong-userspaceid-string-grantname)
    - [GetWorkGroupsWithAnyGrant(long userspaceId, IEnumerable&lt;string&gt; grantNames)](#getworkgroupswithanygrantlong-userspaceid-ienumerableltstringgt-grantnames)
    - [GetWorkGroupsWithAllGrants(long userspaceId, IEnumerable&lt;string&gt; grantNames)](#getworkgroupswithallgrantslong-userspaceid-ienumerableltstringgt-grantnames)
    - [WorkGroups(long userspaceId)](#workgroupslong-userspaceid)
    - [ObjectKey()](#objectkey)
  - [Testing](#testing)
    - [1. Interface implementation class](#1-interface-implementation-class)
    - [2. Extension methods](#2-extension-methods)
    - [3. Practical implementation](#3-practical-implementation)
      - [3.1 Recommended implementation](#31-recommended-implementation)
    - [4. Drawbacks of the solution](#4-drawbacks-of-the-solution)
    - [5. Alternative approaches](#5-alternative-approaches)

<!-- /TOC -->

## Installation

```PowerShell
Install-Package Monq.Core.Authorization
```

## Connection

The simplest way is to call the middleware without arguments: the user grants address is
resolved by the default application name `pl-work-groups-api-service` through the registered
`IMicroserviceAddressProvider`.

```CSharp
builder.Host.UseMicroserviceAddressResolver(
    new KubernetesClusterIpAddressResolver());

...

app.UseMonqAuthorization();
```

For local development outside Kubernetes, configure the resolver once per environment so
that the parameterless call keeps working everywhere:

```CSharp
builder.Host.UseMicroserviceAddressResolver(context =>
    context.HostingEnvironment.IsDevelopment()
        ? new FixedMicroserviceAddressResolver(new Uri("https://api.example.test"))
        : new KubernetesClusterIpAddressResolver());

...

app.UseMonqAuthorization();
```

An already resolved absolute address can also be passed directly for a one-off case:

```CSharp
app.UseMonqAuthorization(new Uri("https://api.example.test"));
```

The name-based overloads require `IMicroserviceAddressProvider` in the DI container.
It is registered automatically by the `Monq.Core.BasicDotNetMicroservice` defaults, by
any `builder.Host.UseMicroserviceAddressResolver(...)` call, or explicitly via
`builder.Services.AddMicroserviceAddressing()`.

Authorization should be connected before `app.UseMvc()` (or before the endpoints are mapped).

### Options

To pass custom options use the overload with `MonqAuthorizationOptions`:

```CSharp
app.UseMonqAuthorization(
    options: new MonqAuthorizationOptions
    {
        UseCache = true,        // permissions caching (true by default)
        CacheTime = TimeSpan.FromSeconds(3) // caching duration (3 seconds by default)
    });
```

`MonqAuthorizationOptions.UserGrantsApiAddress` is set by the `UseMonqAuthorization`
overloads after address resolution; set it directly only if you build a custom integration.

## Migration to 7.0.0

See [v7-MIGRATION.md](v7-MIGRATION.md). In short: the overloads that read `BaseUri` from
`IConfiguration` are removed; use `app.UseMonqAuthorization()` inside Kubernetes, or pass an
explicit `Uri` during local development.

## OpenTelemetry

The library provides an `ActivitySource` named `Monq.Core.Authorization` for tracing
authorization operations.

### Connection

When configuring OpenTelemetry in the application, add the source:

```CSharp
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddSource("Monq.Core.Authorization")
        // ... the other sources
    );
```

### Produced spans

| Name | Kind | Description |
|---|---|---|
| `MonqAuthorization` | Internal | The authorization processing in the middleware |

### Tags

| Tag | Type | Description |
|---|---|---|
| `auth.user.id` | long | The user identifier |
| `auth.skipped` | bool | Authorization skipped (system user or sub == 0) |

> **Note:** HTTP requests to the user grants API are automatically traced via
> `AddHttpClientInstrumentation()`.

## Extension methods

All extension methods are defined in the `Microsoft.AspNetCore.Authorization` namespace.

### Subject()

To obtain the system identifier of the request user from the `ClaimsPrincipal` _User_ property,
use the _Subject()_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var subjectId = User.Subject(); // the request user id (for example, 23).
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Returns a signed 64-bit integer, _long_.

Special cases:

- returns -1 for a system user;
- returns 0 on any error.

### Userspace()

To obtain the identifier of the request user's userspace from the HTTP headers of the
_Request_ property, use the _Userspace()_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var userspaceId = Request.Userspace(); // the userspace id (for example, 1).
        ...
    }
}
```

> The controller _Request_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Returns a signed 64-bit integer, _long_.

Special cases:

- throws `UserspaceNotFoundException` on any error.

### Packets()

To authorize the actions of the request user from the `ClaimsPrincipal` _User_ property in
controllers, use the _Packets()_ extension method, which returns the request user's
permission packets.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var packets = User.Packets(userspaceId); // an enumeration of the user's permission packets.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ -- a signed 64-bit integer, the userspace identifier. For example, `17`.

The method returns `IEnumerable<PacketViewModel>`; the model is defined in the
`Monq.Core.Authorization.Models` NuGet package and has the following significant properties:

- _Id_ -- the permission packet identifier.
- _Name_ -- the permission packet name. For example, `Space administrator`.
- _Description_ -- the permission packet description.
- _IsReadOnly_ -- a flag indicating that the packet is a system one. For example, true.
- _Grants_ -- an enumeration of three-part string grant definitions. For example, `{ "base-system.rsm.read", "cloud-management.grants-meta.read" }`.
- _Owners_ -- the collection of owning work groups and their users for the packet.

For simplicity, permission packets can be treated as work group roles, and packet owners as
the work groups in which those roles are defined.

### IsSystemUser()

To check whether the request user from the `ClaimsPrincipal` _User_ property is a system user
(i.e. another service, a test, etc.), use the _IsSystemUser()_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var hasSystemGrants = User.IsSystemUser(); // true most often means no further checks are needed.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

The method returns `true`:

- if the user's _Claim_s contain a system user identifier;

### IsWorkGroupManager(long userspaceId, long workGroupId)

To check whether the user is a work group manager, use the
_IsWorkGroupManager(long userspaceId, long workGroupId)_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var isManager = User.IsWorkGroupManager(17, 23);
        // true if the user is a manager of work group 23 in userspace 17.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ -- a signed 64-bit integer, the userspace identifier. For example, `17`.
- _workGroupId_ -- a signed 64-bit integer, the work group identifier. For example, `23`.

The method returns `true`:

- if the user is a manager of the selected work group (has the system packet of the `Manager` type);

### HasGrant(long userspaceId, long workGroupId, string grantName)

To check whether the request user from the `ClaimsPrincipal` _User_ property has specific
execution grants in the given work group, use the
_HasGrant(long userspaceId, long workGroupId, string grantName)_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canReadRsm = User.HasGrant(17, 23, "base-system.rsm.read");
        // true if the user has such grants in the given work group.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ -- a signed 64-bit integer, the identifier of the userspace for which the grants are checked. For example, `17`.
- _workGroupId_ -- a signed 64-bit integer, the identifier of the work group in which the grants are checked. For example, `23`.
- _grantName_ -- a string, a three-part user grant name definition. For example, `base-system.rsm.read`.

The method returns `true`:

- if the request user has the requested grants;
- if called by a system user;

### HasAnyGrant(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)

To check whether the request user from the `ClaimsPrincipal` _User_ property has any of the
execution grants in the given work group, use the
_HasAnyGrant(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canReadRsm = User.HasAnyGrant(17, 23, new[] { "base-system.rsm.read", "base-system.rsm.write" });
        // true if the user has the write or read grant in the given work group.
        // the case where a write grant also implies a read grant.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ -- a signed 64-bit integer, the identifier of the userspace for which the grants are checked. For example, `17`.
- _workGroupId_ -- a signed 64-bit integer, the identifier of the work group in which the grants are checked. For example, `23`.
- _grantNames_ -- a variable number of three-part user grant name definitions. For example, `base-system.rsm.read`, `base-system.rsm.write`.

The method returns `true`:

- if the request user has at least one of the requested grants;
- if called by a system user;

### HasAllGrants(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)

To check whether the request user from the `ClaimsPrincipal` _User_ property has all of the
listed execution grants in the given work group, use the
_HasAllGrants(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canAddTimelineRole = User.HasAllGrants(17, 23, new[] { "base-system.timeline.read", "base-system.work-group.roles-write" });
        // true if the user has all of the listed grants in the given work group.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ -- a signed 64-bit integer, the identifier of the userspace for which the grants are checked. For example, `17`.
- _workGroupId_ -- a signed 64-bit integer, the identifier of the work group in which the grants are checked. For example, `23`.
- _grantNames_ -- a variable number of three-part user grant name definitions. For example, `base-system.timeline.read`, `base-system.work-group.roles-write`.

The method returns `true`:

- if the request user has all of the requested grants;
- if called by a system user;

### HasUserspaceAdminPanelGrant(long userspaceId, string adminPanelGrant)

To check whether the request user from the `ClaimsPrincipal` _User_ property has an admin
panel grant, use the _HasUserspaceAdminPanelGrant(long userspaceId, string adminPanelGrant)_
extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canManageUsers = User.HasUserspaceAdminPanelGrant(17, "pl.admins.user-entities-write");
        // true if the user has the admin panel grant in the given userspace.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ -- a signed 64-bit integer, the userspace identifier. For example, `17`.
- _adminPanelGrant_ -- a string, an admin panel grant definition. For example, `pl.admins.user-entities-write`.

The method returns `true`:

- if the request user has the specified admin panel grant in the given userspace;

### HasAnyUserspaceAdminPanelGrant(long userspaceId, IEnumerable&lt;string&gt; adminPanelGrantNames)

To check whether the request user from the `ClaimsPrincipal` _User_ property has at least one
of the admin panel grants, use the
_HasAnyUserspaceAdminPanelGrant(long userspaceId, IEnumerable&lt;string&gt; adminPanelGrantNames)_
extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canManageSomething = User.HasAnyUserspaceAdminPanelGrant(17, new[] { "pl.admins.user-entities-write", "pl.admins.content-write" });
        // true if the user has at least one of the specified admin panel grants.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ -- a signed 64-bit integer, the userspace identifier. For example, `17`.
- _adminPanelGrantNames_ -- a variable number of admin panel grant definitions. For example, `pl.admins.user-entities-write`, `pl.admins.content-write`.

The method returns `true`:

- if the request user has at least one of the specified admin panel grants in the given userspace;

### GetWorkGroupsWithGrant(long userspaceId, string grantName)

To obtain the identifiers of the work groups of the given userspace in which the request user
from the `ClaimsPrincipal` _User_ property has specific grants, use the
_GetWorkGroupsWithGrant(long userspaceId, string grantName)_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var workGroupsWithSetRsmGrant = User.GetWorkGroupsWithGrant(17, "base-system.rsm.read");
        // an enumeration of work group identifiers.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ - a signed 64-bit integer, the userspace identifier. For example, `17`.

- _grantName_ - a string, a three-part user grant name definition. For example, `base-system.rsm.read`.

The method returns an enumeration of signed 64-bit integers, `IEnumerable<long>`.

### GetWorkGroupsWithAnyGrant(long userspaceId, IEnumerable&lt;string&gt; grantNames)

To obtain the identifiers of the work groups of the given userspace in which the request user
from the `ClaimsPrincipal` _User_ property has at least one of the listed grants, use the
_GetWorkGroupsWithAnyGrant(long userspaceId, IEnumerable&lt;string&gt; grantNames)_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var workGroupsWithGetRsmGrant = User.GetWorkGroupsWithAnyGrant(17, new[] { "base-system.rsm.write", "base-system.rsm.read" });
        // an enumeration of work group identifiers.
        // the case where a write grant implies a read grant.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ - a signed 64-bit integer, the userspace identifier. For example, `17`.

- _grantNames_ -- a variable number of three-part user grant name definitions. For example, `base-system.rsm.write`, `base-system.rsm.read`.

The method returns an enumeration of signed 64-bit integers, `IEnumerable<long>`.

### GetWorkGroupsWithAllGrants(long userspaceId, IEnumerable&lt;string&gt; grantNames)

To obtain the identifiers of the work groups of the given userspace in which the request user
from the `ClaimsPrincipal` _User_ property has all of the listed grants, use the
_GetWorkGroupsWithAllGrants(long userspaceId, IEnumerable&lt;string&gt; grantNames)_ extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var workGroupsWithUserAdministration = User.GetWorkGroupsWithAllGrants(17, new [] { "base-system.work-group.users-write", "base-system.work-group.roles-write" });
        // an enumeration of work group identifiers.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Arguments:

- _userspaceId_ - a signed 64-bit integer, the userspace identifier. For example, `17`.

- _grantNames_ -- a variable number of three-part user grant name definitions. For example, `base-system.work-group.users-write`, `base-system.work-group.roles-write`.

The method returns an enumeration of signed 64-bit integers, `IEnumerable<long>`.

### WorkGroups(long userspaceId)

To obtain the identifiers of the work groups in which the request user from the
`ClaimsPrincipal` _User_ property has any grants, use the _WorkGroups(long userspaceId)_
extension method.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var userWorkGroups = User.WorkGroups(17);
        // an enumeration of work group identifiers.
        ...
    }
}
```

> The controller _User_ property is inherited from `ControllerBase` in the
> `Microsoft.AspNetCore.Mvc` namespace.

Argument:

- _userspaceId_ - a signed 64-bit integer, the userspace identifier. For example, `17`.

The method returns an enumeration of signed 64-bit integers, `IEnumerable<long>`.

### ObjectKey()

To generate a unique key for a service user, use the _ObjectKey()_ extension method.

```CSharp
var objectKey = user.ObjectKey(); // for example, "smon-res-owner:12345"
```

The method returns a string in the `objectType:objectId` format composed from the
corresponding user claims, or `null` if the required claims are missing.

## Testing

To simplify unit testing of controllers and services that use the user permissions library,
the extension methods (see [Extension methods](#extension-methods)) implement the same-named
methods of the `IGrantsExtensions` interface; thus, the library facade is fully substitutable.

Below is the instruction for the recommended substitution of the extension methods when
unit-testing controller methods that use the library's extension methods.

### 1. Interface implementation class

The library includes a reference implementation of the substitution class for
`IGrantsExtensions`. This was done to achieve two main goals:

- avoiding repetition of the same code in the tests of projects that use authorization
  (it is assumed that most projects will use it);
- avoiding the need to change every implementation when the API evolves.

The reference implementation resides in the `Monq.Core.Authorization.Tests` namespace and is
implemented by the `FakeGrantsImpl` class. The interface implementation method calls are
reassigned to the corresponding functions, each of which is available by default as a class
property. The naming rule for the property holding the function is
`extension method name` + `Func`. Thus, to substitute the _Subject()_ extension method,
provide your own implementation of _SubjectFunc_ by overriding it (see below).

In addition, the reference implementation includes the _Assign()_ method, which makes it the
currently used permissions implementation.

Example:

```CSharp
public class FakeGrantsImpl : IGrantsExtensions
{
    ...
    public Func<ClaimsPrincipal?, long>? SubjectFunc { get; set; }
    public long Subject(ClaimsPrincipal? user) =>
        SubjectFunc?.Invoke(user) ?? _defaultImpl.Subject(user);

    public void Assign() => GrantsExtensions.Implementation = this;
    ...
}
```

### 2. Extension methods

The logic, i.e. substituting the missing functions with the ones used in a given test, is
moved to a separate extension-methods class on the test library side, because a reference
implementation of such methods cannot exist. Still, the reference implementation falls back
to the default implementation when a substitutable function is not set, so some tests in a
proper environment may not require substituting _every_ method (like _UseSubject()_ in the
example below).

This approach allows a more flexible creation of the permission extension method substitution
instance via a "fluent interface" (Martin Fowler) through constructor method chains
(method chaining, Eric Evans).

Minimal examples of completely ignoring the existing environment properties are methods like:

```CSharp
public static class FakeGrantsExtensions
{
    ...
    public static FakeGrantsImpl FakeSubject(this FakeGrantsImpl fakeGrants, long subjectId)
    {
        fakeGrants.SubjectFunc = (user) => subjectId;
        return fakeGrants;
    }

    public static FakeGrantsImpl FakeHasGrant(this FakeGrantsImpl fakeGrants, bool value)
    {
        fakeGrants.HasGrantFunc = (user, userspaceId, workGroup, grantName) => value;
        return fakeGrants;
    }
    ...
}
```

The first method sets the expected user identifier to a predefined value; the second makes
_any_ call to _HasGrant()_ return `true`.

Note that _all methods must accept an instance of the `IGrantsExtensions` implementation class
(see [above](#1-interface-implementation-class)) and return the same instance_.

A more comprehensive approach (in this context) is using the real request subject (which is
overridden somewhere else) and assigning specific permissions to that subject. Therefore, the
extension method implementations can be complemented with methods like:

```CSharp
public static class FakeGrantsExtensions
{
    ...
    const sbyte SystemUserId = -1;
    const sbyte DefaultUserId = 0;

    public static FakeGrantsImpl UseSubject(this FakeGrantsImpl fakeGrants)
    {
        fakeGrants.SubjectFunc = (user) =>
        {
            if (user is null)
                return DefaultUserId;
            var userSub = user.Claims.FirstOrDefault(x => x.Type == SubjectClaim)?.Value;

            if (string.IsNullOrWhiteSpace(userSub))
            {
                var isSystemUser = IsSystemUser(user);
                if (isSystemUser)
                    return SystemUserId;
                return DefaultUserId;
            }

            if (!long.TryParse(userSub, out var userId))
                return DefaultUserId;
            return userId;
        };
        return fakeGrants;
    }
    ...
}
```

> Generally repeats the library method of obtaining the user identifier from their
> `ClaimsPrincipal`: `0` on any error and `-1` for a system user.

and

```CSharp
public static class FakeGrantsExtensions
{
    ...
    public static FakeGrantsImpl FakeHasGrant(this FakeGrantsImpl fakeGrants, long subjectId, long workGroupId, string grant)
    {
        fakeGrants.HasGrantFunc = (user, userspaceId, workGroup, grantName) =>
        {
            if (user.Subject() == subjectId
                && workGroup == workGroupId
                && grantName == grant)
                return true;

            return false;
        };
        return fakeGrants;
    }
    ...
}
```

> Allows specifying in which work group the given user has the specified grants. The work
> group and user identifiers and the string grant representation are passed as parameters.

> **Attention** This _HasGrant()_ implementation uses _Subject()_, so to use it in the current
> substituted permissions instance, the substitution of that method must also be implemented.

### 3. Practical implementation

As an example, consider a code snippet inspired by the
[HasGrant(long userspaceId, long workGroupId, string grant) description](#hasgrantlong-userspaceid-long-workgroupid-string-grantname)
and a hypothetical test that could be written using [the techniques described above](#2-extension-methods).

The tested snippet will look like this:

```CSharp
[HttpGet]
public async Task<IActionResult> GetAll()
{
    ...
    var workGroupId = _workGroupService.GetWorkGroupId();
    var canReadRsm = User.HasGrant(userspaceId, workGroupId, "base-system.rsm.read");
    if (!canReadRsm)
        return StatusCode(StatusCodes.Status403Forbidden);
    ...
}
```

> **Remark** The implementation is significantly simplified. Of course, in a real application
> the variable initialization is more complex, and constants are moved to a separate class or
> taken from the database.

In this example we ~~miraculously~~ obtain a work group identifier and check whether the user
has RSM read permissions in it.

#### 3.1 Recommended implementation

Based on our implementation, the test conditions can be set as follows:

```CSharp
[Fact(DisplayName = "TestController: GetAll: Checking proper test data retrieval.")]
public async Task ShouldProperlyGetAll()
{
    var subjectId = _sporadic.GetId();
    var workGroupId = await CreateWorkGroup(subjectId);

    var fakeGrants = new FakeGrantsImpl()
        .UseSubject()
        .FakeHasGrant(subjectId, workGroupId, "base-system.rsm.read");
    fakeGrants.Assign();
    ...
}
```

After the call to _fakeGrants.Assign();_ the call to the extension method
_User.HasGrant(userspaceId, workGroupId, "base-system.rsm.read");_ is redirected to the new
`FakeGrantsImpl` instance, where that method invokes our overridden _HasGrantFunc_ function.
Since the _HasGrantFunc_ implementation in our case directly calls another extension method,
_Subject()_, it is also overridden by the _UseSubject()_ extension. Obviously, such an
implementation is only possible in tests that override the controller context user.

```CSharp
TestController CreateController(long subjectId)
{
    var controller = new TestController();
    controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
    controller.HttpContext.User = new ClaimsPrincipal(
      new ClaimsIdentity(
        new Claim[] { new Claim(JwtClaimTypes.Subject, subjectId.ToString()) },
        string.Empty, JwtClaimTypes.Name, JwtClaimTypes.Role));
    return controller;
}
```

To replace the used implementation of the (static) authorization extension methods with the
default implementation, just call the _RevertToDefaults()_ method of `FakeGrantsImpl`.

```CSharp
[Fact(DisplayName = "TestController: GetAll: Checking proper test data retrieval.")]
public async Task ShouldProperlyGetAll()
{
    var fakeGrants = new FakeGrantsImpl()
        .FakeIsSystemUser(true); // Substitutes the IsSystemUser() method.
    fakeGrants.Assign();
    ... // Test execution.
    fakeGrants.RevertToDefaults(); // Use IsSystemUser() by default.
}
```

### 4. Drawbacks of the solution

The main drawback of this approach is the impossibility of sequentially semantically setting
one substitutable function, for example:

```CSharp
var fakeGrants = new FakeGrantsImpl()
    .UseSubject()
    .FakeHasGrant(subjectId, workGroupId, "base-system.rsm.read")
    .FakeHasGrant(subjectId, workGroupId, "base-system.work-group.read");
fakeGrants.Assign();
```

> In this example only the second grant will be set, and the call to
> _User.HasGrant(userspaceId, workGroupId, "base-system.rsm.read")_ will return `false`.

As a solution for such situations, overloads that accept multiple grants are suggested,
for example:

```CSharp
public static FakeGrantsImpl FakeHasGrant(this FakeGrantsImpl fakeGrants, long subjectId, long workGroupId, IEnumerable<string> grants)
{
    fakeGrants.HasGrantFunc = (user, userspaceId, workGroup, grantName) =>
    {
        if (user.Subject() == subjectId
            && workGroup == workGroupId
            && grants.Contains(grantName))
            return true;

        return false;
    };
    return fakeGrants;
}
```

Such an overload allows rewriting the previous example in the following (usable) way:

```CSharp
var fakeGrants = new FakeGrantsImpl()
    .UseSubject()
    .FakeHasGrant(subjectId, workGroupId,
        new[] { "base-system.rsm.read", "base-system.work-group.read" });
fakeGrants.Assign();
```

Another alternative could be multiple permission substitution instances, which most often has
no practical use in real tests.

### 5. Alternative approaches

It is assumed that adding a third level of testing abstraction, namely a pseudo-collection of
grants, would allow overriding the functions in `FakeGrantsImpl` with almost the same ones as
the originals, the only difference being that they would refer to their own grants repository.

Together with the significantly increased effort of writing and maintaining such tests and
the minor gain obtained in return, such an approach will most often be excessive.

Another alternative -- an implicit grants storage in the `FakeGrantsImpl` instance itself,
populated _together_ with the function overrides -- seems more suitable for use in real projects.
