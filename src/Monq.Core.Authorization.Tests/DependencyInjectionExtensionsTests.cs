using Xunit;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Monq.Core.MicroserviceAddressing.Addressing;
using Moq;
using System;

namespace Monq.Core.Authorization.Tests;

#pragma warning disable CA1822 // Mark members as static
public class DependencyInjectionExtensionsTests
{
    [Fact]
    public void ShouldResolveUserGrantsAddressByApplicationName()
    {
        const string applicationName = "work-groups-api";
        var addressProvider = CreateAddressProvider(applicationName);

        var app = CreateApp(addressProvider.Object);
        app.UseMonqAuthorization(applicationName);

        addressProvider.Verify(x => x.Resolve(
            applicationName,
            MicroserviceProtocol.Http,
            null,
            null), Times.Once);
    }

    [Fact(DisplayName = "DependencyInjectionExtensions: UseMonqAuthorization() resolves the default user grants application name.")]
    public void ShouldResolveDefaultUserGrantsApplicationName()
    {
        var addressProvider = CreateAddressProvider(DependencyInjectionExtensions.DefaultUserGrantsApplicationName);

        var app = CreateApp(addressProvider.Object);
        app.UseMonqAuthorization();

        addressProvider.Verify(x => x.Resolve(
            DependencyInjectionExtensions.DefaultUserGrantsApplicationName,
            MicroserviceProtocol.Http,
            null,
            null), Times.Once);
    }

    [Fact(DisplayName = "DependencyInjectionExtensions: UseMonqAuthorization(Uri) requires no address provider.")]
    public void ShouldUseExplicitUriWithoutAddressProvider()
    {
        var app = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());

        app.UseMonqAuthorization(new Uri("http://user-grants.example.com"));
    }

    [Fact(DisplayName = "DependencyInjectionExtensions: UseMonqAuthorization(Uri) rejects relative addresses.")]
    public void ShouldRejectRelativeUserGrantsAddress()
    {
        var app = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());

        Assert.Throws<ArgumentException>(() =>
            app.UseMonqAuthorization(new Uri("/user-grants", UriKind.Relative)));
    }

    [Fact(DisplayName = "DependencyInjectionExtensions: UseMonqAuthorization(string) rejects empty application names.")]
    public void ShouldRejectEmptyApplicationName()
    {
        var app = CreateApp(new Mock<IMicroserviceAddressProvider>().Object);

        Assert.Throws<ArgumentException>(() => app.UseMonqAuthorization(" "));
    }

    // TODO: Придумать метод тестирования, который не будет требовать псевдо-сервера.
    [Fact(DisplayName = "DependencyInjectionExtensions: UseMonqAuthorization(): Проверка корректного добавления middleware.",
        Skip = "Придумать метод тестирования, который не будет требовать псевдо-сервера.")]
    public void ShouldProperlyAddMiddlewareToPipeline()
    {
        // TODO: Рассмотреть Smocks: https://github.com/vanderkleij/Smocks
        // TODO: Рассмотреть AppDomainToolkit: https://github.com/jduv/AppDomainToolkit
    }

    static Mock<IMicroserviceAddressProvider> CreateAddressProvider(string applicationName)
    {
        var addressProvider = new Mock<IMicroserviceAddressProvider>();
        addressProvider
            .Setup(x => x.Resolve(
                applicationName,
                MicroserviceProtocol.Http,
                null,
                null))
            .Returns(new ResolvedMicroserviceAddress(
                new Uri("http://work-groups-api.namespace.svc.cluster.local")));
        return addressProvider;
    }

    static IApplicationBuilder CreateApp(IMicroserviceAddressProvider addressProvider)
    {
        var services = new ServiceCollection();
        services.AddSingleton(addressProvider);
        return new ApplicationBuilder(services.BuildServiceProvider());
    }
}
