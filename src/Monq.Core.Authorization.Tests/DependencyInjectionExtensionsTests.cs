using Xunit;

namespace Monq.Core.Authorization.Tests;

#pragma warning disable CA1822 // Mark members as static
public class DependencyInjectionExtensionsTests
{
    // TODO: Придумать метод тестирования, который не будет требовать псевдо-сервера.
    [Fact(DisplayName = "DependencyInjectionExtensions: UseMonqAuthorization(): Проверка корректного добавления middleware.",
        Skip = "Придумать метод тестирования, который не будет требовать псевдо-сервера.")]
    public void ShouldProperlyAddMiddlewareToPipeline()
    {
        // TODO: Рассмотреть Smocks: https://github.com/vanderkleij/Smocks
        // TODO: Рассмотреть AppDomainToolkit: https://github.com/jduv/AppDomainToolkit
    }
}
