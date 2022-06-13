using System;
using System.Runtime.Serialization;

namespace Monq.Core.Authorization.Exceptions
{
    /// <summary>
    /// Представление ошибки отсутствия пользовательского пространства в заголовках.
    /// </summary>
    public class UserspaceNotFoundException : Exception
    {
        /// <summary>Initializes a new instance of the <see cref="UserspaceNotFoundException"></see> class.</summary>
        public UserspaceNotFoundException()
        {
        }

        /// <summary>Initializes a new instance of the <see cref="UserspaceNotFoundException"></see> class with serialized data.</summary>
        /// <param name="info">The <see cref="SerializationInfo"></see> that holds the serialized object data about the exception being thrown.</param>
        /// <param name="context">The <see cref="StreamingContext"></see> that contains contextual information about the source or destination.</param>
        /// <exception cref="ArgumentNullException">The <paramref name="info">info</paramref> parameter is null.</exception>
        /// <exception cref="SerializationException">The class name is null or <see cref="Exception.HResult"></see> is zero (0).</exception>
        protected UserspaceNotFoundException(SerializationInfo info, in StreamingContext context) : base(info, context)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="UserspaceNotFoundException"></see> class with a specified error message.</summary>
        /// <param name="message">The message that describes the error.</param>
        public UserspaceNotFoundException(string message) : base(message)
        {
        }

        /// <summary>Initializes a new instance of the <see cref="UserspaceNotFoundException"></see> class with a specified error message and a reference to the inner exception that is the cause of this exception.</summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference (Nothing in Visual Basic) if no inner exception is specified.</param>
        public UserspaceNotFoundException(string message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}
