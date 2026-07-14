# monq-core-authorization

Библиотека служит обёрткой для методов запроса пользовательских прав у сервера авторизации.

<!-- TOC depthFrom:2 -->

- [monq-core-authorization](#monq-core-authorization)
  - [Установка](#%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0)
  - [Подключение](#%D0%BF%D0%BE%D0%B4%D0%BA%D0%BB%D1%8E%D1%87%D0%B5%D0%BD%D0%B8%D0%B5)
  - [OpenTelemetry](#opentelemetry)
  - [Реализуемые методы расширения](#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D1%83%D0%B5%D0%BC%D1%8B%D0%B5-%D0%BC%D0%B5%D1%82%D0%BE%D0%B4%D1%8B-%D1%80%D0%B0%D1%81%D1%88%D0%B8%D1%80%D0%B5%D0%BD%D0%B8%D1%8F)
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
  - [Тестирование](#%D1%82%D0%B5%D1%81%D1%82%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5)
    - [1. Класс-реализация интерфейса](#1-%D0%BA%D0%BB%D0%B0%D1%81%D1%81-%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D1%8F-%D0%B8%D0%BD%D1%82%D0%B5%D1%80%D1%84%D0%B5%D0%B9%D1%81%D0%B0)
    - [2. Методы расширения](#2-%D0%BC%D0%B5%D1%82%D0%BE%D0%B4%D1%8B-%D1%80%D0%B0%D1%81%D1%88%D0%B8%D1%80%D0%B5%D0%BD%D0%B8%D1%8F)
    - [3. Практическая реализация](#3-%D0%BF%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%B5%D1%81%D0%BA%D0%B0%D1%8F-%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D1%8F)
      - [3.1 Рекомендуемая реализация](#31-%D1%80%D0%B5%D0%BA%D0%BE%D0%BC%D0%B5%D0%BD%D0%B4%D1%83%D0%B5%D0%BC%D0%B0%D1%8F-%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D1%8F)
    - [4. Недостатки решения](#4-%D0%BD%D0%B5%D0%B4%D0%BE%D1%81%D1%82%D0%B0%D1%82%D0%BA%D0%B8-%D1%80%D0%B5%D1%88%D0%B5%D0%BD%D0%B8%D1%8F)
    - [5. Альтернативные подходы](#5-%D0%B0%D0%BB%D1%8C%D1%82%D0%B5%D1%80%D0%BD%D0%B0%D1%82%D0%B8%D0%B2%D0%BD%D1%8B%D0%B5-%D0%BF%D0%BE%D0%B4%D1%85%D0%BE%D0%B4%D1%8B)

<!-- /TOC -->

## Установка

```PowerShell
Install-Package Monq.Core.Authorization
```

## Подключение

Для корректного подключения один из поставщиков конфигурации приложения _должен_ содержать значение ключа "`BaseUri`" с адресом сервиса пользовательских прав.

Для задания опций и подключения _Middleware_ в методе конфигурации (_Configure()_) приложения следует указать:

```CSharp
public IConfiguration Configuration { get; set; }

public Startup(IConfiguration configuration)
    => Configuration = configuration;

public void Configure(IApplicationBuilder app)
{
    ...
    app.UseMonqAuthorization(Configuration);
    ...
    app.UseMvc();
}
```

Подключение авторизации следует производить перед _app.UseMvc()_.

### Опции

Для передачи пользовательских опций используйте перегрузку с `MonqAuthorizationOptions`:

```CSharp
app.UseMonqAuthorization(new MonqAuthorizationOptions
{
    UseCache = true,        // кэширование прав (по умолчанию true)
    CacheTime = TimeSpan.FromSeconds(3) // длительность кэширования (по умолчанию 3 сек)
}, Configuration);
```

## OpenTelemetry

Библиотека предоставляет `ActivitySource` с именем `Monq.Core.Authorization` для трассировки операций авторизации.

### Подключение

При настройке OpenTelemetry в приложении добавьте источник:

```CSharp
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddSource("Monq.Core.Authorization")
        // ... остальные источники
    );
```

### Создаваемые span'ы

| Имя | Kind | Описание |
|---|---|---|
| `MonqAuthorization` | Internal | Процесс обработки авторизации в middleware |

### Теги

| Тег | Тип | Описание |
|---|---|---|
| `auth.user.id` | long | Идентификатор пользователя |
| `auth.skipped` | bool | Авторизация пропущена (системный пользователь или sub == 0) |

> **Примечание:** HTTP-запросы к сервису пользовательских прав автоматически трассируются через `AddHttpClientInstrumentation()`.

## Реализуемые методы расширения

Все методы расширения определены в пространстве имён `Microsoft.AspNetCore.Authorization`.

### Subject()

Для сценариев, в которых необходимо получить системный идентификатор пользователя запроса из `ClaimsPrincipal` свойства _User_, используется метод расширения _Subject()_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var subjectId = User.Subject(); // id пользователя запроса (например, 23).
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Возвращает значение типа 64-разрядное знаковое целое, _long_.

Особые случаи:

- для системного пользователя возвращает -1;
- в случае любой ошибки возвращает 0.

### Userspace()

Для сценариев, в которых необходимо получить идентификатор пространства пользователя запроса из HTTP-заголовков свойства _Request_, используется метод расширения _Userspace()_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var userspaceId = Request.Userspace(); // id пользовательского пространства (например, 1).
        ...
    }
}
```

> Свойство контроллера _Request_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Возвращает значение типа 64-разрядное знаковое целое, _long_.

Особые случаи:

- в случае любой ошибки возвращает исключение типа `UserspaceNotFoundException`.

### Packets()

Для авторизации действий пользователя запроса из `ClaimsPrincipal` свойства _User_ в контроллерах используется метод расширения _Packets()_, который позволит получить пакеты прав пользователя запроса.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var packets = User.Packets(userspaceId); // перечисление пакетов прав пользователя.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства. Например, `17`.

Метод возвращает значение типа перечисление `IEnumerable<PacketViewModel>`, модель определена в NuGet-пакете `Monq.Core.Authorization.Models` со значимыми свойствами:

- _Id_ -- идентификатор пакета прав.
- _Name_ -- имя пакета прав. Например, `Администратор пространства`.
- _Description_ -- описание пакета прав.
- _IsReadOnly_ -- флаг принадлежности пакета к системным. Например, true.
- _Grants_ -- перечисление строковых трёхсоставных определений прав. Например, `{ "base-system.rsm.read", "cloud-management.grants-meta.read" }`.
- _Owners_ -- коллекция рабочих групп-владельцев и их пользователей пакета прав.

Для простоты восприятия можно воспринимать пакеты прав как роли рабочих групп, владельцев пакетов -- как рабочие группы, в которых эти роли определены.

### IsSystemUser()

Для проверки, является ли пользователь запроса из `ClaimsPrincipal` свойства _User_ системным пользователем (т.е. другим сервисом, тестом и т.д.) используется метод расширения _IsSystemUser()_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var hasSystemGrants = User.IsSystemUser(); // true чаще всего означает отсутствие дальнейших проверок.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Метод возвращает `true`:

- если у пользователя в его _Claim_ 'ах присутствует идентификатор системного пользователя;

### IsWorkGroupManager(long userspaceId, long workGroupId)

Для проверки, является ли пользователь менеджером рабочей группы, используется метод расширения _IsWorkGroupManager(long userspaceId, long workGroupId)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var isManager = User.IsWorkGroupManager(17, 23);
        // true, если пользователь является менеджером рабочей группы 23 в пространстве 17.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства. Например, `17`.
- _workGroupId_ -- 64-разрядное знаковое целое, идентификатор рабочей группы. Например, `23`.

Метод возвращает `true`:

- если пользователь является менеджером выбранной рабочей группы (имеет системный пакет типа `Manager`);

### HasGrant(long userspaceId, long workGroupId, string grantName)

Для проверки наличия конкретных прав исполнения в данной рабочей группе у пользователя запроса из `ClaimsPrincipal` свойства _User_ используется метод расширения _HasGrant(long userspaceId, long workGroupId, string grantName)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canReadRsm = User.HasGrant(17, 23, "base-system.rsm.read");
        // true, если у пользователя есть такие права в данной рабочей группе.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства, для которого проверяются соответствующие права. Например, `17`.
- _workGroupId_ -- 64-разрядное знаковое целое, идентификатор рабочей группы, в которой проверяются соответствующие права. Например, `23`.
- _grantName_ -- строка, трёхчленное определение имени пользовательского права. Например, `base-system.rsm.read`.

Метод возвращает `true`:

- если у пользователя запроса есть запрашиваемые права;
- если вызван системным пользователем;

### HasAnyGrant(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)

Для проверки наличия какого-либо из прав исполнения в данной рабочей группе у пользователя запроса из `ClaimsPrincipal` свойства _User_ используется метод расширения _HasAnyGrant(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canReadRsm = User.HasAnyGrant(17, 23, new[] { "base-system.rsm.read", "base-system.rsm.write" });
        // true, если у пользователя есть право записи или чтения в данной рабочей группе.
        // случай, когда право на запись предполагает и право чтения.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства, для которого проверяются соответствующие права. Например, `17`.
- _workGroupId_ -- 64-разрядное знаковое целое, идентификатор рабочей группы, в которой проверяются соответствующие права. Например, `23`.
- _grantNames_ -- переменное количество строк, трёхчленных определений имени пользовательского права. Например, `base-system.rsm.read`, `base-system.rsm.write`.

Метод возвращает `true`:

- если у пользователя запроса есть хотя бы одно из запрашиваемых прав;
- если вызван системным пользователем;

### HasAllGrants(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)

Для проверки наличия всех перечисленных прав исполнения в данной рабочей группе у пользователя запроса из `ClaimsPrincipal` свойства _User_ используется метод расширения _HasAllGrants(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canAddTimelineRole = User.HasAllGrants(17, 23, new[] { "base-system.timeline.read", "base-system.work-group.roles-write" });
        // true, если у пользователя есть все перечисленные права в данной рабочей группе.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства, для которого проверяются соответствующие права. Например, `17`.
- _workGroupId_ -- 64-разрядное знаковое целое, идентификатор рабочей группы, в которой проверяются соответствующие права. Например, `23`.
- _grantNames_ -- переменное количество строк, трёхчленных определений имени пользовательского права. Например, `base-system.timeline.read`, `base-system.work-group.roles-write`.

Метод возвращает `true`:

- если у пользователя запроса есть все запрашиваемые права;
- если вызван системным пользователем;

### HasUserspaceAdminPanelGrant(long userspaceId, string adminPanelGrant)

Для проверки наличия права из админ. панели у пользователя запроса из `ClaimsPrincipal` свойства _User_ используется метод расширения _HasUserspaceAdminPanelGrant(long userspaceId, string adminPanelGrant)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canManageUsers = User.HasUserspaceAdminPanelGrant(17, "pl.admins.user-entities-write");
        // true, если у пользователя есть право админ. панели в данном пространстве.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства. Например, `17`.
- _adminPanelGrant_ -- строка, определение права админ. панели. Например, `pl.admins.user-entities-write`.

Метод возвращает `true`:

- если у пользователя запроса есть указанное право админ. панели в данном пространстве;

### HasAnyUserspaceAdminPanelGrant(long userspaceId, IEnumerable&lt;string&gt; adminPanelGrantNames)

Для проверки наличия хотя бы одного из прав админ. панели у пользователя запроса из `ClaimsPrincipal` свойства _User_ используется метод расширения _HasAnyUserspaceAdminPanelGrant(long userspaceId, IEnumerable&lt;string&gt; adminPanelGrantNames)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canManageSomething = User.HasAnyUserspaceAdminPanelGrant(17, new[] { "pl.admins.user-entities-write", "pl.admins.content-write" });
        // true, если у пользователя есть хотя бы одно из указанных прав админ. панели.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства. Например, `17`.
- _adminPanelGrantNames_ -- переменное количество строк, определений прав админ. панели. Например, `pl.admins.user-entities-write`, `pl.admins.content-write`.

Метод возвращает `true`:

- если у пользователя запроса есть хотя бы одно из указанных прав админ. панели в данном пространстве;

### GetWorkGroupsWithGrant(long userspaceId, string grantName)

Для получения идентификаторов рабочих групп данного пользовательского пространства, в которых у пользователя запроса из `ClaimsPrincipal` свойства _User_ есть конкретные права, используется метод расширения _GetWorkGroupsWithGrant(long userspaceId, string grantName)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var workGroupsWithSetRsmGrant = User.GetWorkGroupsWithGrant(17, "base-system.rsm.read");
        // перечисление идентификаторов рабочих групп.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ - 64-разрядное знаковое целое, идентификатор пользовательского пространства, администрирование которого проверяется. Например, `17`.

- _grantName_ - строка, трёхчленное определение имени пользовательского права. Например, `base-system.rsm.read`.

Метод возвращает значение типа перечисление 64-разрядных знаковых целых, `IEnumerable<long>`.

### GetWorkGroupsWithAnyGrant(long userspaceId, IEnumerable&lt;string&gt; grantNames)

Для получения идентификаторов рабочих групп данного пользовательского пространства, в которых у пользователя запроса из `ClaimsPrincipal` свойства _User_ есть хотя бы одно из перечисленных прав, используется метод расширения _GetWorkGroupsWithAnyGrant(long userspaceId, IEnumerable&lt;string&gt; grantNames)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var workGroupsWithGetRsmGrant = User.GetWorkGroupsWithAnyGrant(17, new[] { "base-system.rsm.write", "base-system.rsm.read" });
        // перечисление идентификаторов рабочих групп.
        // случай, когда право на запись подразумевает права чтения.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ - 64-разрядное знаковое целое, идентификатор пользовательского пространства, администрирование которого проверяется. Например, `17`.

- _grantNames_ -- переменное количество строк, трёхчленных определений имени пользовательского права. Например, `base-system.rsm.write`, `base-system.rsm.read`.

Метод возвращает значение типа перечисление 64-разрядных знаковых целых, `IEnumerable<long>`.

### GetWorkGroupsWithAllGrants(long userspaceId, IEnumerable&lt;string&gt; grantNames)

Для получения идентификаторов рабочих групп данного пользовательского пространства, в которых у пользователя запроса из `ClaimsPrincipal` свойства _User_ есть все перечисленные права, используется метод расширения _GetWorkGroupsWithAllGrants(long userspaceId, IEnumerable&lt;string&gt; grantNames)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var workGroupsWithUserAdministration = User.GetWorkGroupsWithAllGrants(17, new [] { "base-system.work-group.users-write", "base-system.work-group.roles-write" });
        // перечисление идентификаторов рабочих групп.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ - 64-разрядное знаковое целое, идентификатор пользовательского пространства, администрирование которого проверяется. Например, `17`.

- _grantNames_ -- переменное количество строк, трёхчленных определений имени пользовательского права. Например, `base-system.work-group.users-write`, `base-system.work-group.roles-write`.

Метод возвращает значение типа перечисление 64-разрядных знаковых целых, `IEnumerable<long>`.

### WorkGroups(long userspaceId)

Для получения идентификаторов рабочих групп, в которых у пользователя запроса из `ClaimsPrincipal` свойства _User_ есть какие-либо права, используется метод расширения _WorkGroups(long userspaceId)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var userWorkGroups = User.WorkGroups(17);
        // перечисление идентификаторов рабочих групп.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргумент:

- _userspaceId_ - 64-разрядное знаковое целое, идентификатор пользовательского пространства, администрирование которого проверяется. Например, `17`.

Метод возвращает значение типа перечисление 64-разрядных знаковых целых, `IEnumerable<long>`.

### ObjectKey()

Для генерации уникального ключа сервисного пользователя используется метод расширения _ObjectKey()_.

```CSharp
var objectKey = user.ObjectKey(); // например, "smon-res-owner:12345"
```

Метод возвращает строку в формате `objectType:objectId`, составленную из соответствующих claims пользователя, или `null` при отсутствии необходимых claims.

## Тестирование

Для упрощения модульного тестирования контроллеров и сервисов, которые используют библиотеку пользовательских прав, методы расширения (см. [Реализуемые методы расширения](#реализуемые-методы-расширения)) реализуют одноимённые методы интерфейса `IGrantsExtensions`, таким образом, фасад библиотеки является полностью подменяемым.

Ниже следует инструкция по рекомендуемой подмене методов расширения в модульном тестировании методов контроллеров, в которых используются методы расширения библиотеки.

### 1. Класс-реализация интерфейса

Библиотека включает в себя эталонную имплементацию класса-подмены `IGrantsExtensions`. Это сделано для достижения двух основных целей:

- избегания повторения однотипного кода в тестах проектов, использующих авторизацию (предполагается, что таких будет большинство);
- отсутствия необходимости вносить изменения в каждую из реализаций при дальнейших изменениях API.

Эталонная имплементация содержится в пространстве имён `Monq.Core.Authorization.Tests` и реализуется классом `FakeGrantsImpl`. Вызовы методов реализации интерфейса переназначены на соответствующие им функции, каждая из которых по умолчанию доступна как свойство класса. Правило именования содержащих функции свойств такое `Имя метода расширения` + `Func`. Таким образом, для подмены метода расширения _Subject()_ необходимо задать собственную реализацию _SubjectFunc_, переопределив её (см. ниже).

Кроме того, эталонная реализация включает метод _Assign()_, позволяющий назначить её в качестве текущей используемой реализации прав.

Пример:

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

### 2. Методы расширения

Логика, т.е. подмена отсутствующих функций используемыми в данном тесте, в такой реализации выносится в отдельный класс с методами расширения -- уже на стороне тестовой библиотеки, потому что эталонной реализации таких методов быть не может. Тем не менее, эталонная реализация в случае отсутствия подменяемых функций обращается к реализации по умолчанию, поэтому некоторые тесты в корректном окружении могут не требовать подмены _каждого_ из методов (как _UseSubject()_ из примера ниже).

Такой подход позволяет более гибкое создание экземпляра подмены методов расширения прав в рамках "текучего интерфейса" (_fluent interface_, Martin Fowler) через цепочки методов (_method chaining_, Eric Evans) конструктора.

Минималистичными примерами полного игнорирования существующих свойств окружения могут быть такие методы:

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

Первый из методов устанавливает предполагаемый идентификатор пользователя предзаданным значением; второй устанавливает для _любого_ вызова _HasGrant()_ значение `true`.

Стоит обратить внимание на то, что _все методы должны принимать экземпляр класса-реализации интерфейса `IGrantsExtensions` (см. [выше](#1-класс-реализация-интерфейса)) и возвращать его же.

Более комплексным подходом будет (в данном контексте) использование реального субъекта запроса (который переопределяется где-то ещё) и задание конкретных прав этому субъекту. Поэтому реализацию методов расширения можно дополнить методами:

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

> В целом повторяет библиотечный метод получения идентификатора пользователя по его `ClaimsPrincipal`, `0` при любой ошибке и `-1` для системного пользователя.

и

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

> Позволяет задать, в какой рабочей группе у данного пользователя есть указанные права. Идентификаторы рабочей группы и пользователя, а также строковое представление прав передаются аргументами в параметры.

> **Внимание** Данная реализация _HasGrant()_ использует _Subject()_, поэтому для использования в текущем экземпляре подменных прав требуется имплементировать в т.ч. и подмену этого метода.

### 3. Практическая реализация

Для примера рассмотрим участок кода, навеянный [описанием метода расширения HasGrant(long userspaceId, long workGroupId, string grant)](#hasgrantlong-userspaceid-long-workgroupid-string-grant), и гипотетический тест, который с помощью [описанных выше техник](#2-методы-расширения) могли бы написать.

Тестируемый участок будет выглядеть следующим образом:

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

> **Ремарка** Реализация существенно упрощена. Конечно, в реальном приложении инициализация переменных сложнее, а константы вынесены в отдельный класс или берутся из базы.

В этом примере мы каким-то ~~чудесным~~ образом получаем идентификатор рабочей группы и проверяем, есть ли у пользователя в ней права на чтение РСМ.

#### 3.1 Рекомендуемая реализация

Опираясь на нашу реализацию, можно задать тестовые условия следующим образом:

```CSharp
[Fact(DisplayName = "TestController: GetAll: Проверка корректного получения тестовых данных.")]
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

После вызова _fakeGrants.Assign();_ обращение к методу расширения _User.HasGrant(userspaceId, workGroupId, "base-system.rsm.read");_ будет перенаправлено в новый экземпляр `FakeGrantsImpl`, где этот метод вызовет переопределённую нами функцию _HasGrantFunc_. Поскольку имплементация _HasGrantFunc_ в нашем случае прямо обращается к другому методу расширения, _Subject()_, также переопределяемому расширением _UseSubject()_. Конечно, такая реализация возможна только при использовании тестов, переопределяющих пользователя контекста контроллера.

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

Для того, чтобы заменить используемую реализацию (статических) методов расширения для работы с авторизацией на имплементацию по умолчанию, достаточно вызвать _RevertToDefaults()_-метод `FakeGrantsImpl`.

```CSharp
[Fact(DisplayName = "TestController: GetAll: Проверка корректного получения тестовых данных.")]
public async Task ShouldProperlyGetAll()
{
    var fakeGrants = new FakeGrantsImpl()
        .FakeIsSystemUser(true); // Подменяется метод IsSystemUser()
    fakeGrants.Assign();
    ... // Выполнение тестов
    fakeGrants.RevertToDefaults(); // Использовать IsSystemUser() по умолчанию
}
```

### 4. Недостатки решения

Главным недостатком такого подхода является невозможность последовательной семантической установки одной заменяемой функции, например:

```CSharp
var fakeGrants = new FakeGrantsImpl()
    .UseSubject()
    .FakeHasGrant(subjectId, workGroupId, "base-system.rsm.read")
    .FakeHasGrant(subjectId, workGroupId, "base-system.work-group.read");
fakeGrants.Assign();
```

>В этом примере будет установлено только второе право, а вызов _User.HasGrant(userspaceId, workGroupId, "base-system.rsm.read")_ вернёт `false`.

В качестве решения для указанных ситуаций предлагаются перегрузки, принимающие множество прав, например:

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

Такая перегрузка позволит переписать прошлый пример следующим (работопригодным) образом:

```CSharp
var fakeGrants = new FakeGrantsImpl()
    .UseSubject()
    .FakeHasGrant(subjectId, workGroupId,
        new[] { "base-system.rsm.read", "base-system.work-group.read" });
fakeGrants.Assign();
```

Другой альтернативой могут служить множественные экземпляры подмены прав, что чаще всего не имеет практического приложения в реальных тестах.

### 5. Альтернативные подходы

Предполагается, что добавление третьего уровня абстракции тестирования, а именно -- псевдоколлекции прав, позволит переопределить функции в `FakeGrantsImpl` на почти аналогичные исходным, с тем лишь исключением, что ссылаться они будут на собственный репозиторий прав.

Вкупе с существенно возрастающей трудоёмкостью написания и поддержки таких тестов и незначительным выигрышем, получаемым взамен, чаще всего такой подход будет избыточным.

Другая альтернатива -- неявное хранилище прав в данном экземпляре `FakeGrantsImpl`, которое заполняется _вместе_ с переопределением функций, кажется более пригодной к использованию в реальных проектах.
