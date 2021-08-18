namespace Monq.Core.Authorization
{
    // TODO: Подумать от том, чтобы сделать открытым.
    // TODO: В таком случае, придётся делать "конструктор", чтобы не возникало курьёзов в духе cloud-management.rsm.users-write.
    internal static class Modules
    {
        /// <summary>
        /// Специальное право для системного пользователя.
        /// </summary>
        internal const string OnlySystemUser = "only.system.user";

        internal static class System
        {
            /// <summary>
            /// Базовая система.
            /// </summary>
            internal const string BaseSystem = "base-system";

            /// <summary>
            /// Облачное управление.
            /// </summary>
            internal const string CloudManagement = "cloud-management";
        }

        internal static class Functional
        {
            /// <summary>
            /// Рабочая группа.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            internal const string WorkGroup = "work-group";

            /// <summary>
            /// Рабочая группа.
            /// </summary>
            internal const string BaseSystemWorkGroup = "base-system.work-group";

            /// <summary>
            /// Рассылки.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            internal const string Deliveries = "deliveries";

            /// <summary>
            /// Рассылки.
            /// </summary>
            internal const string BaseSystemDeliveries = "base-system.deliveries";

            /// <summary>
            /// Шкала времени (рабочие режимы).
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            internal const string Timeline = "timeline";

            /// <summary>
            /// Шкала времени (рабочие режимы).
            /// </summary>
            internal const string BaseSystemTimeline = "base-system.timeline";

            /// <summary>
            /// Ресурсно-сервисная модель.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            internal const string Rsm = "rsm";

            /// <summary>
            /// Ресурсно-сервисная модель.
            /// </summary>
            internal const string BaseSystemRsm = "base-system.rsm";

            /// <summary>
            /// Правила и действия.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            internal const string RulesAndActions = "rules-and-actions";

            /// <summary>
            /// Правила и действия.
            /// </summary>
            internal const string BaseSystemRulesAndActions = "base-system.rules-and-actions";

            /// <summary>
            /// Виджеты.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            internal const string Widgets = "widgets";

            /// <summary>
            /// Виджеты.
            /// </summary>
            internal const string BaseSystemWidgets = "base-system.widgets";

            /// <summary>
            /// Мета-права.
            /// </summary>
            /// <remarks>
            /// Системный модуль Облачное управление (cloud-management).
            /// </remarks>
            internal const string GrantsMeta = "grants-meta";

            /// <summary>
            /// Мета-права.
            /// </summary>
            internal const string CloudManagementGrantsMeta = "cloud-management.grants-meta";
        }

        internal static class GrantType
        {
            /// <summary>
            /// Чтение пользовательских прав.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            /// <remarks>
            /// Функциональный модуль Рабочая группа (work-group).
            /// </remarks>
            internal const string WorkGroupRolesRead = "roles-read";

            /// <summary>
            /// Чтение пользовательских прав.
            /// </summary>
            internal const string BaseSystemWorkGroupRolesRead = "base-system.work-group.roles-read";

            /// <summary>
            /// Внесение/изменение пользовательских прав.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            /// <remarks>
            /// Функциональный модуль Рабочая группа (work-group).
            /// </remarks>
            internal const string WorkGroupRolesWrite = "roles-write";

            /// <summary>
            /// Внесение/изменение пользовательских прав.
            /// </summary>
            internal const string BaseSystemWorkGroupRolesWrite = "base-system.work-group.roles-write";

            /// <summary>
            /// Чтение рабочих групп.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            /// <remarks>
            /// Функциональный модуль Рабочая группа (work-group).
            /// </remarks>
            internal const string WorkGroupRead = "read";

            /// <summary>
            /// Чтение рабочих групп.
            /// </summary>
            internal const string BaseSystemWorkGroupRead = "base-system.work-group.read";

            /// <summary>
            /// Внесение/изменение рабочих групп.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            /// <remarks>
            /// Функциональный модуль Рабочая группа (work-group).
            /// </remarks>
            internal const string WorkGroupWrite = "write";

            /// <summary>
            /// Внесение/изменение рабочих групп.
            /// </summary>
            internal const string BaseSystemWorkGroupWrite = "base-system.work-group.write";

            /// <summary>
            /// Чтение рассылок рабочей группы.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            /// <remarks>
            /// Функциональный модуль Рабочая группа (work-group).
            /// </remarks>
            internal const string WorkGroupDeliveriesRead = "deliveries-read";

            /// <summary>
            /// Чтение рассылок рабочей группы.
            /// </summary>
            internal const string BaseSystemWorkGroupDeliveriesRead = "base-system.work-group.deliveries-read";

            /// <summary>
            /// Внесение/изменение рассылок рабочей группы.
            /// </summary>
            /// <remarks>
            /// Системный модуль Базовая система (base-system).
            /// </remarks>
            /// <remarks>
            /// Функциональный модуль Рабочая группа (work-group).
            /// </remarks>
            internal const string WorkGroupDeliveriesWrite = "deliveries-write";

            /// <summary>
            /// Внесение/изменение рассылок рабочей группы.
            /// </summary>
            internal const string BaseSystemWorkGroupDeliveriesWrite = "base-system.work-group.deliveries-write";

            /// <summary>
            /// Чтение мета-прав.
            /// </summary>
            /// <remarks>
            /// Системный модуль Облачное управление (cloud-management).
            /// </remarks>
            /// <remarks>
            /// Функциональный модуль Мета-права (grants-meta).
            /// </remarks>
            internal const string GrantsMetaRead = "read";

            /// <summary>
            /// Чтение мета-прав.
            /// </summary>
            internal const string CloudManagementGrantsMetaRead = "cloud-management.grants-meta.read";

            /// <summary>
            /// Внесение/изменение мета-прав.
            /// </summary>
            /// <remarks>
            /// Системный модуль Облачное управление (cloud-management).
            /// </remarks>
            /// <remarks>
            /// Функциональный модуль Мета-права (grants-meta).
            /// </remarks>
            internal const string GrantsMetaWrite = "write";

            /// <summary>
            /// Внесение/изменение мета-прав.
            /// </summary>
            internal const string CloudManagementGrantsMetaWrite = "cloud-management.grants-meta.write";
        }
    }
}
