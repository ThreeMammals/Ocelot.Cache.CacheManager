using CacheManager.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Ocelot.Configuration;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using System.Reflection;

namespace Ocelot.Cache.CacheManager.UnitTests;

public class OcelotBuilderExtensionsTests : UnitTest
{
    private readonly IServiceCollection _services;
    private readonly IConfiguration _configRoot;
    private IOcelotBuilder? _ocelotBuilder;
    private readonly int _maxRetries;
    private Exception? _ex;

    public OcelotBuilderExtensionsTests()
    {
        _configRoot = new ConfigurationRoot([]);
        _services = new ServiceCollection();
        _services.AddSingleton(GetHostingEnvironment());
        _services.AddSingleton(_configRoot);
        _maxRetries = 100;
    }

    private static IWebHostEnvironment GetHostingEnvironment()
    {
        var environment = new Mock<IWebHostEnvironment>();
        environment
            .Setup(e => e.ApplicationName)
            .Returns(typeof(OcelotBuilderExtensionsTests).GetTypeInfo().Assembly.GetName().Name ?? string.Empty);

        return environment.Object;
    }

    [Fact]
    public void Should_set_up_cache_manager()
    {
        WhenISetUpOcelotServices();
        WhenISetUpCacheManager();
        Assert.Null(_ex);
        OnlyOneVersionOfEachCacheIsRegistered();
    }

    private void OnlyOneVersionOfEachCacheIsRegistered()
    {
        var outputCache = _services.Single(x => x.ServiceType == typeof(IOcelotCache<CachedResponse>));
        var outputCacheManager = _services.Single(x => x.ServiceType == typeof(ICacheManager<CachedResponse>));
        var instance = (ICacheManager<CachedResponse>)outputCacheManager.ImplementationInstance!;
        var ocelotConfigCache = _services.Single(x => x.ServiceType == typeof(IOcelotCache<IInternalConfiguration>));
        var ocelotConfigCacheManager = _services.Single(x => x.ServiceType == typeof(ICacheManager<IInternalConfiguration>));
        var fileConfigCache = _services.Single(x => x.ServiceType == typeof(IOcelotCache<FileConfiguration>));
        var fileConfigCacheManager = _services.Single(x => x.ServiceType == typeof(ICacheManager<FileConfiguration>));

        Assert.Equal(_maxRetries, instance.Configuration.MaxRetries);
        Assert.NotNull(outputCache);
        Assert.NotNull(ocelotConfigCache);
        Assert.NotNull(ocelotConfigCacheManager);
        Assert.NotNull(fileConfigCache);
        Assert.NotNull(fileConfigCacheManager);
    }

    private void WhenISetUpOcelotServices()
    {
        try
        {
            _ocelotBuilder = _services.AddOcelot(_configRoot);
        }
        catch (Exception e)
        {
            _ex = e;
        }
    }

    private void WhenISetUpCacheManager()
    {
        try
        {
            _ocelotBuilder.AddCacheManager(x =>
            {
                x.WithMaxRetries(_maxRetries);
                x.WithDictionaryHandle();
            });
        }
        catch (Exception e)
        {
            _ex = e;
        }
    }
}
