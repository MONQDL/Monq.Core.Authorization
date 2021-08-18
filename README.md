# monq-core-authorization

Библиотека служит обёрткой для методов запроса пользовательских прав у сервера авторизации.

<!-- TOC depthFrom:2 -->

- [monq-core-authorization](#monq-core-authorization)
  - [История изменений](#%D0%B8%D1%81%D1%82%D0%BE%D1%80%D0%B8%D1%8F-%D0%B8%D0%B7%D0%BC%D0%B5%D0%BD%D0%B5%D0%BD%D0%B8%D0%B9)
    - [4.0](#40)
    - [3.2](#32)
    - [3.0](#30)
    - [2.1](#21)
  - [Установка](#%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0)
  - [Подключение](#%D0%BF%D0%BE%D0%B4%D0%BA%D0%BB%D1%8E%D1%87%D0%B5%D0%BD%D0%B8%D0%B5)
  - [Реализуемые методы расширения](#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D1%83%D0%B5%D0%BC%D1%8B%D0%B5-%D0%BC%D0%B5%D1%82%D0%BE%D0%B4%D1%8B-%D1%80%D0%B0%D1%81%D1%88%D0%B8%D1%80%D0%B5%D0%BD%D0%B8%D1%8F)
    - [Subject()](#subject)
    - [Userspace()](#userspace)
    - [Packets()](#packets)
    - [IsSystemUser()](#issystemuser)
    - [IsUserspaceAdmin(long userspaceId)](#isuserspaceadminlong-userspaceid)
    - [IsSuperUser(long userspaceId)](#issuperuserlong-userspaceid)
    - [HasGrant(long userspaceId, long workGroupId, string grantName)](#hasgrantlong-userspaceid-long-workgroupid-string-grantname)
    - [HasAnyGrant(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)](#hasanygrantlong-userspaceid-long-workgroupid-ienumerableltstringgt-grantnames)
    - [HasAllGrants(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)](#hasallgrantslong-userspaceid-long-workgroupid-ienumerableltstringgt-grantnames)
    - [GetWorkGroupsWithGrant(long userspaceId, string grantName)](#getworkgroupswithgrantlong-userspaceid-string-grantname)
    - [GetWorkGroupsWithAnyGrant(long userspaceId, IEnumerable&lt;string&gt; grantNames)](#getworkgroupswithanygrantlong-userspaceid-ienumerableltstringgt-grantnames)
    - [GetWorkGroupsWithAllGrants(long userspaceId, IEnumerable&lt;string&gt; grantNames)](#getworkgroupswithallgrantslong-userspaceid-ienumerableltstringgt-grantnames)
    - [WorkGroups(long userspaceId)](#workgroupslong-userspaceid)
    - [Userspaces()](#userspaces)
  - [Тестирование](#%D1%82%D0%B5%D1%81%D1%82%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5)
    - [1. Класс-реализация интерфейса](#1-%D0%BA%D0%BB%D0%B0%D1%81%D1%81-%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D1%8F-%D0%B8%D0%BD%D1%82%D0%B5%D1%80%D1%84%D0%B5%D0%B9%D1%81%D0%B0)
    - [2. Методы расширения](#2-%D0%BC%D0%B5%D1%82%D0%BE%D0%B4%D1%8B-%D1%80%D0%B0%D1%81%D1%88%D0%B8%D1%80%D0%B5%D0%BD%D0%B8%D1%8F)
    - [3. Практическая реализация](#3-%D0%BF%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%B5%D1%81%D0%BA%D0%B0%D1%8F-%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D1%8F)
      - [3.1 Рекомендуемая реализация](#31-%D1%80%D0%B5%D0%BA%D0%BE%D0%BC%D0%B5%D0%BD%D0%B4%D1%83%D0%B5%D0%BC%D0%B0%D1%8F-%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D1%8F)
    - [4. Недостатки решения](#4-%D0%BD%D0%B5%D0%B4%D0%BE%D1%81%D1%82%D0%B0%D1%82%D0%BA%D0%B8-%D1%80%D0%B5%D1%88%D0%B5%D0%BD%D0%B8%D1%8F)
    - [5. Альтернативные подходы](#5-%D0%B0%D0%BB%D1%8C%D1%82%D0%B5%D1%80%D0%BD%D0%B0%D1%82%D0%B8%D0%B2%D0%BD%D1%8B%D0%B5-%D0%BF%D0%BE%D0%B4%D1%85%D0%BE%D0%B4%D1%8B)

<!-- /TOC -->

## История изменений

### 4.0

- Произведено обновление до .NET Core 3.0

### 3.2

- Переломные изменения:
    - Удалено свойство владельца пакета прав _openWorkGroups_. Значения идентификаторов рабочих групп, которым предоставляется доступ к пакету, больше не учитываются.

### 3.0

- Переломные изменения:
    - Подключение библиотеки авторизации теперь не требует отдельного класса опций авторизации. Вместо этого используются стандартные поставщики конфигурации приложения; сервис пользовательских прав задаётся ключом "`BaseUri`".
    - Перечисленные ниже методы теперь требуют обязательного указания идентификатора пользовательского пространства:
        - [HasGrant(long userspaceId, long workGroupId, string grantName)](#hasgrantlong-userspaceid-long-workgroupid-string-grantname)
        - [HasAnyGrant(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)](#hasanygrantlong-userspaceid-long-workgroupid-ienumerable&ltstring&gt-grantnames)
        - [HasAllGrants(long userspaceId, long workGroupId, IEnumerable&lt;string&gt; grantNames)](#hasallgrantslong-userspaceid-long-workgroupid-ienumerable&ltstring&gt-grantnames)
    - Удалён _IsCloudAdmin()_ как избыточный и не отвечающий требованиям безопасности.
    - Метод [IsUserspaceAdmin()](#isuserspaceadminlong-userspaceid) теперь возвращает `false` для системного пользователя.
    - Удалено _AutoAssign_-свойство псевдореализации прав `FakeGrantsImpl`.
    - _RevertToDefaults()_ перенесён из `GrantsExtensions` в `FakeGrantsImpl`, где имеет больше смысла и не требует добавления дополнительных пространств имён.
- Улучшения:
    - Методы [HasGrant()](#hasgrantlong-userspaceid-long-workgroupid-string-grantname), [HasAnyGrant()](#hasanygrantlong-userspaceid-long-workgroupid-ienumerable&ltstring&gt-grantnames), [HasAllGrants()](#hasallgrantslong-userspaceid-long-workgroupid-ienumerable&ltstring&gt-grantnames) теперь безусловно возвращают `true`, если вызваны администратором пользовательского пространства (аналогично системному пользователю).
    - Добавлен метод [IsSuperUser()](#issuperuserlong-userspaceid) для проверки пользователя на права системного пользователя или администратора данного пространства.

### 2.1

- Переломные изменения:
    - Перечисленные ниже методы теперь требуют обязательного указания идентификатора пользовательского пространства:
        - [GetWorkGroupsWithGrant(long userspaceId, string grantName)](#getworkgroupswithgrantlong-userspaceid-string-grantname)
        - [GetWorkGroupsWithAnyGrant(long userspaceId, IEnumerable&lt;string&gt; grantNames)](#getworkgroupswithanygrantlong-userspaceid-ienumerable&ltstring&gt-grantnames)
        - [GetWorkGroupsWithAllGrants(long userspaceId, IEnumerable&lt;string&gt; grantNames)](#getworkgroupswithallgrantslong-userspaceid-ienumerable&ltstring&gt-grantnames)
        - [WorkGroups(long userspaceId)](#workgroupslong-userspaceid)
    - При невозможности получить идентификатор пользовательского пространства в методе [Userspace()](#userspace) теперь _не возвращается_ значение по умолчанию (было `0`), а выбрасывается исключение типа `UserspaceNotFoundException`.

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
        var packets = User.Packets(); // перечисление пакетов прав пользователя.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Метод возвращает значение типа перечисление с моделью `PacketViewModel`, определённой в соответствующем файле проекта (_src\Monq.Core.Authorization\ViewModels\PacketViewModel.cs_), со значимыми свойствами:

```CSharp
public class PacketViewModel
{
    /// <summary>
    /// Идентификатор пакета пользовательских прав.
    /// </summary>
    public long Id { get; set; }

    /// <summary>
    /// Имя пакета пользовательских прав.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Описание пакета пользовательских прав.
    /// </summary>
    public string Description { get; set; }

    /// <summary>
    /// Является ли пакет доступным только для чтения.
    /// </summary>
    public bool IsReadOnly { get; set; }

    /// <summary>
    /// Коллекция прав доступа пакета.
    /// </summary>
    public IEnumerable<string> Grants { get; set; }

    /// <summary>
    /// Коллекция владельцев пакета.
    /// </summary>
    public IEnumerable<PacketOwnerViewModel> Owners { get; set; }
}
```

Где значимые:

- _Name_ -- имя пакета прав. Например, `Администратор пространства`.
- _IsReadOnly_ -- флаг принадлежности пакета к системным. Например, true.
- _Grants_ -- перечисление строковых трёхсоставных определений прав. Например, `{ "base-system.rsm.read", "cloud-management.grants-meta.read" }`.
- _Owners_ -- коллекция рабочих групп-владельцев и их пользователей пакета прав.

..., -- и, соответственно, `PacketOwnerViewModel`, определённой в соответствующем файле проекта (_src\Monq.Core.Authorization\ViewModels\PacketOwnerViewModel.cs_), со значимыми свойствами:

```CSharp
public class PacketOwnerViewModel
{
    /// <summary>
    /// Идентификатор рабочей группы-владельца пакета.
    /// </summary>
    public long WorkGroupId { get; set; }

    /// <summary>
    /// Идентификатор пользовательского пространства.
    /// </summary>
    public long UserspaceId { get; set; }

    /// <summary>
    /// Коллекция идентификаторов пользователей пакета.
    /// </summary>
    public IEnumerable<long> Users { get; set; }
}
```

Где:

- _WorkGroupId_ -- идентификатор рабочей группы в сервисе рабочих групп. Например, `23`.
- _UserspaceId_ -- идентификатор пользовательского пространства рабочей группы. Например, `1`.
- _Users_ -- коллекция идентификаторов пользователей рабочей группы, имеющих доступ до прав пакета. Например, `{ 1, 15, 41 }`.

..., -- которые позволяют вкупе исчерпывающе определить права пользователя в каждой рабочей группе.

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

### IsUserspaceAdmin(long userspaceId)

Для проверки наличия прав администрирования данного облачного пространства у пользователя запроса из `ClaimsPrincipal` свойства _User_ используется метод расширения _IsUserspaceAdmin(long userspaceId)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canCreateWorkGroups = User.IsUserspaceAdmin(17);
        // true, если пользователь администрирует данное пользовательское пространство.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства, администрирование которого проверяется. Например, `17`.

Метод возвращает `true`:

- если пользователь является администратором данного пользовательского пространства;

### IsSuperUser(long userspaceId)

Для проверки наличия прав системного пользователя или администрирования данного облачного пространства у пользователя запроса из `ClaimsPrincipal` свойства _User_ используется метод расширения _IsSuperUser(long userspaceId)_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var canCreateWorkGroups = User.IsSuperUser(17);
        // true, если пользователь является системным или администрирует данное пользовательское пространство.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Аргументы:

- если у пользователя в его _Claim_ 'ах присутствует идентификатор системного пользователя;
- _userspaceId_ -- 64-разрядное знаковое целое, идентификатор пользовательского пространства, администрирование которого проверяется. Например, `17`.

Метод возвращает `true`:

- если пользователь является администратором данного пользовательского пространства;

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
- если вызван администратором запрашиваемого пользовательского пространства;

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
- если вызван администратором запрашиваемого пользовательского пространства;

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
- _grantNames_ -- переменное количество строк, трёхчленных определений имени пользовательского права. Например, `base-system.timeline.read`, `base-system.work-group.roles-write"`.

Метод возвращает `true`:

- если у пользователя запроса есть все запрашиваемые права;
- если вызван системным пользователем;
- если вызван администратором запрашиваемого пользовательского пространства;

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

### Userspaces()

Для получения идентификаторов пространств пользователя, в рабочих группах которых у пользователя запроса из `ClaimsPrincipal` свойства _User_ есть какие-либо права, используется метод расширения _Userspaces()_.

```CSharp
[Route("api/test")]
public class TestController : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        ...
        var allUserspaces = User.Userspaces();
        // перечисление идентификаторов пространств пользователя.
        ...
    }
}
```

> Свойство контроллера _User_ унаследовано из `ControllerBase` в пространстве имён `Microsoft.AspNetCore.Mvc`.

Метод возвращает значение типа перечисление 64-разрядных знаковых целых, `IEnumerable<long>`.

## Тестирование

Для упрощения модульного тестирования контроллеров и сервисов, которые используют библиотеку пользовательских прав, методы расширения (см. [Реализуемые методы расширения](#реализуемые-методы-расширения)) реализуют одноимённые методы интерфейса `IGrantsExtensions`, таким образом, фасад библиотеки является полностью подменяемым.

Ниже следует инструкция по рекомендуемой подмене методов расширения в модульном тестировании методов контроллеров, в которых используются методы расширения библиотеки.

### 1. Класс-реализация интерфейса

Начиная с версии `1.2.0` библиотека включает в себя эталонную имплементацию класса-подмены `IGrantsExtensions`. Это сделано для достижения двух основных целей:

- избегания повторения однотипного кода в тестах проектов, использующих авторизацию (предполагается, что таких будет большинство);
- отсутствия необходимости вносить изменения в каждую из реализаций при дальнейших изменениях API.

Эталонная имплементация содержится в пространстве имён `Monq.Core.Authorization.Tests` и реализуется классом `FakeGrantsImpl`. Вызовы методов реализации интерфейса переназначены на соответствующие им функции, каждая из которых по умолчанию доступна как свойство класса. Правило именования содержащих функции свойств такое `Имя метода расширения` + `Func`. Таким образом, для подмены метода расширения _Subject()_ необходимо задать собственную реализацию _SubjectFunc_, переопределив её (см. ниже).

Кроме того, эталонная реализация включает метод _Assign()_, позволяющий назначить её в качестве текущей используемой реализации прав.

Пример:

```CSharp
public class FakeGrantsImpl : IGrantsExtensions
{
    ...
    public Func<ClaimsPrincipal, long> SubjectFunc { get; set; }
    public long Subject(ClaimsPrincipal user) => SubjectFunc(user);

    public void Assign() => GrantsExtensions.Implementation = this;
    ...
}
```

Кроме того, реализуется свойство _AutoAssign_, которое может указывать используемой реализации функций на необходимость автоматического вызова метода _Assign()_ при назначении. Его назначение вынесено в конструктор.

```CSharp
public class FakeGrantsImpl : IGrantsExtensions
{
    ...
    public bool AutoAssign { get; set; }
    public FakeGrantsImpl(bool autoAssign = false) => AutoAssign = autoAssign;
    ...
}
```

> **Ремарка** В общем случае, использование _AutoAssign_ будет считаться дурным тоном (антипаттерном), потому как реализует и полагается на побочный эффект; но в определённых ситуациях может быть полезным, поэтому такая возможность на страницах этого руководства не только упоминается, но и рассматривается.

### 2. Методы расширения

Логика, т.е. подмена отсутствующих функций используемыми в данном тесте, в такой реализации выносится в отдельный класс с методами расширения -- уже на стороне тестовой библиотеки, потому что эталонной реализации таких методов быть не может. Тем не менее, начиная с версии `1.3.1` библиотеки эталонная реализация в случае отсутствия подменяемых функций обращается к реализации по умолчанию, поэтому некоторые тесты в корректном окружении могут не требовать подмены _каждого_ из методов (как _UseSubject()_ из примера ниже).

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
        fakeGrants.HasGrantFunc = (user, workGroup, grantName) => value;
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
        fakeGrants.HasGrantFunc = (user, workGroup, grantName) =>
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

Для примера рассмотрим участок кода, навеянный [описанием метода расширения HasGrant(long workGroupId, string grant)](#hasgrantlong-workgroupid-string-grant), и гипотетический тест, который с помощью [описанных выше техник](#2-методы-расширения) могли бы написать.

Тестируемый участок будет выглядеть следующим образом:

```CSharp
[HttpGet]
public async Task<IActionResult> GetAll()
{
    ...
    var workGroupId = _workGroupService.GetWorkGroupId();
    var canReadRsm = User.HasGrant(workGroupId, "base-system.rsm.read");
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

После вызова _fakeGrants.Assign();_ обращение к методу расширения _User.HasGrant(workGroupId, "base-system.rsm.read");_ будет перенаправлено в новый экземпляр `FakeGrantsImpl`, где этот метод вызовет переопределённую нами функцию _HasGrantFunc_. Поскольку имплементация _HasGrantFunc_ в нашем случае прямо обращается к другому методу расширения, _Subject()_, также переопределяемому расширением _UseSubject()_. Конечно, такая реализация возможна только при использовании тестов, переопределяющих пользователя контекста контроллера.

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
{.
    var fakeGrants = new FakeGrantsImpl()
        .FakeIsSystemUser(true); // Подменяется метод IsSystemUser()
    fakeGrants.Assign();
    ... // Выполнение тестов
    fakeGrants.RevertToDefaults(); // Использовать IsSystemUser() по умолнчаию
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

>В этом примере будет установлено только второе право, а вызов _User.HasGrant(workGroupId, "base-system.rsm.read")_ вернёт `false`.

В качестве решения для указанных ситуаций предлагаются перегрузки, принимающие множество прав, например:

```CSharp
public static FakeGrantsImpl FakeHasGrant(this FakeGrantsImpl fakeGrants, long subjectId, long workGroupId, IEnumerable<string> grants)
{
    fakeGrants.HasGrantFunc = (user, workGroup, grantName) =>
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
