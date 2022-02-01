using System.Collections.Generic;

namespace Monq.Core.Authorization
{
    // TODO: Подумать от том, чтобы сделать открытым.
    // TODO: В таком случае, придётся делать "конструктор", чтобы не возникало курьёзов в духе cloud-management.rsm.users-write.
    internal static class Modules
    {
        internal static class GrantType
        {
            /// <summary>
            /// Чтение пользовательских прав.
            /// </summary>
            internal const string BaseSystemWorkGroupRolesRead = "base-system.work-group.roles-read";

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
            /// Внесение/изменение мета-прав.
            /// </summary>
            internal const string CloudManagementGrantsMetaWrite = "cloud-management.grants-meta.write";

            /// <summary>
            /// Право админ. панели на доступ к сущностям пользователя.
            /// </summary>
            internal const string AdminsUserEntitiesWrite = "pl.admins.user-entities-write";

            /// <summary>
            /// Префикс прав админ. панели.
            /// </summary>
            internal const string AdminsGrantPrefix = "pl.admins.";
        }
    }
}
