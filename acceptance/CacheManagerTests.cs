using CacheManager.Core;
using Microsoft.AspNetCore.Http;
using Ocelot.Configuration.File;
using Ocelot.DependencyInjection;
using Ocelot.Testing;
using System.Net;
using System.Text;
using TestStack.BDDfy;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace Ocelot.Cache.CacheManager.Acceptance;

public sealed class CacheManagerTests : AcceptanceSteps
{
    private const string Hello_from_Tom = "Hello from Tom";
    private const string Hello_from_Laura = "Hello from Laura";
    private int _counter = 0;

    public CacheManagerTests()
    { }

    [Fact]
    public void Should_return_cached_response()
    {
        var port = PortFinder.GetRandomPort();
        var options = new FileCacheOptions
        {
            TtlSeconds = 100,
        };
        var configuration = GivenFileConfiguration(port, options);

        this.Given(x => x.GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, Hello_from_Laura, null, null))
            .And(x => GivenThereIsAConfiguration(configuration))
            .And(x => GivenOcelotIsRunningWithCacheManager())
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))
            .Given(x => x.GivenTheServiceNowReturns(port, HttpStatusCode.OK, Hello_from_Tom, null, null))
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))
            .And(x => ThenTheContentLengthIs(Hello_from_Laura.Length))
            .BDDfy();
    }

    [Fact]
    public void Should_return_cached_response_with_expires_header()
    {
        var port = PortFinder.GetRandomPort();
        var options = new FileCacheOptions
        {
            TtlSeconds = 100,
        };
        var configuration = GivenFileConfiguration(port, options);
        var headerExpires = "Expires";
        this.Given(x => x.GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, Hello_from_Laura, headerExpires, "-1"))
            .And(x => GivenThereIsAConfiguration(configuration))
            .And(x => GivenOcelotIsRunningWithCacheManager())
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))
            .Given(x => x.GivenTheServiceNowReturns(port, HttpStatusCode.OK, Hello_from_Tom, null, null))
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))
            .And(x => ThenTheContentLengthIs(Hello_from_Laura.Length))
            .And(x => ThenTheResponseContentHeaderIs(headerExpires, "-1"))
            .BDDfy();
    }

    [Fact]
    public void Should_return_cached_response_when_using_jsonserialized_cache()
    {
        var port = PortFinder.GetRandomPort();
        var options = new FileCacheOptions
        {
            TtlSeconds = 100,
        };
        var configuration = GivenFileConfiguration(port, options);

        this.Given(x => x.GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, Hello_from_Laura, null, null))
            .And(x => GivenThereIsAConfiguration(configuration))
            .And(x => x.GivenOcelotIsRunningWithCacheManager(true))
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))
            .Given(x => x.GivenTheServiceNowReturns(port, HttpStatusCode.OK, Hello_from_Tom, null, null))
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))
            .BDDfy();
    }

    [Fact]
    public void Should_not_return_cached_response_as_ttl_expires()
    {
        var port = PortFinder.GetRandomPort();
        var options = new FileCacheOptions
        {
            TtlSeconds = 1,
        };
        var configuration = GivenFileConfiguration(port, options);

        this.Given(x => x.GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, Hello_from_Laura, null, null))
            .And(x => GivenThereIsAConfiguration(configuration))
            .And(x => GivenOcelotIsRunningWithCacheManager())
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))
            .Given(x => x.GivenTheServiceNowReturns(port, HttpStatusCode.OK, Hello_from_Tom, null, null))
            .And(x => GivenTheCacheExpires())
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Tom))
            .BDDfy();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Trait("Feat", "2058")] // https://github.com/ThreeMammals/Ocelot/pull/2058
    [Trait("Bug", "2059")] // https://github.com/ThreeMammals/Ocelot/issues/2059
    public void Should_return_different_cached_response_when_request_body_changes_and_EnableContentHashing_is_true(bool asGlobalConfig)
    {
        var port = PortFinder.GetRandomPort();
        var options = new FileCacheOptions
        {
            TtlSeconds = 100,
            EnableContentHashing = true,
        };
        var (testBody1String, testBody2String) = TestBodiesFactory();
        var configuration = GivenFileConfiguration(port, options, asGlobalConfig);

        this.Given(x => x.GivenThereIsAnEchoServiceRunningOn(port))
            .And(x => GivenThereIsAConfiguration(configuration))
            .And(x => GivenOcelotIsRunningWithCacheManager())
            .When(x => WhenIPostUrlOnTheApiGateway("/", new StringContent(testBody1String, Encoding.UTF8, "application/json")))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(testBody1String))
            .When(x => WhenIPostUrlOnTheApiGateway("/", new StringContent(testBody2String, Encoding.UTF8, "application/json")))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(testBody2String))
            .When(x => WhenIPostUrlOnTheApiGateway("/", new StringContent(testBody1String, Encoding.UTF8, "application/json")))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(testBody1String))
            .When(x => WhenIPostUrlOnTheApiGateway("/", new StringContent(testBody2String, Encoding.UTF8, "application/json")))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(testBody2String))
            .And(x => ThenTheCounterValueShouldBe(2))
            .BDDfy();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Trait("Feat", "2058")]
    [Trait("Bug", "2059")]
    public void Should_return_same_cached_response_when_request_body_changes_and_EnableContentHashing_is_false(bool asGlobalConfig)
    {
        var port = PortFinder.GetRandomPort();
        var options = new FileCacheOptions
        {
            TtlSeconds = 100,
        };
        var (testBody1String, testBody2String) = TestBodiesFactory();
        var configuration = GivenFileConfiguration(port, options, asGlobalConfig);

        this.Given(x => x.GivenThereIsAnEchoServiceRunningOn(port))
            .And(x => GivenThereIsAConfiguration(configuration))
            .And(x => GivenOcelotIsRunningWithCacheManager())
            .When(x => WhenIPostUrlOnTheApiGateway("/", new StringContent(testBody1String, Encoding.UTF8, "application/json")))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(testBody1String))
            .When(x => WhenIPostUrlOnTheApiGateway("/", new StringContent(testBody2String, Encoding.UTF8, "application/json")))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(testBody1String))
            .When(x => WhenIPostUrlOnTheApiGateway("/", new StringContent(testBody1String, Encoding.UTF8, "application/json")))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(testBody1String))
            .When(x => WhenIPostUrlOnTheApiGateway("/", new StringContent(testBody2String, Encoding.UTF8, "application/json")))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(testBody1String))
            .And(x => ThenTheCounterValueShouldBe(1))
            .BDDfy();
    }

    [Fact]
    [Trait("Issue", "1172")]
    public void Should_clean_cached_response_by_cache_header_via_new_caching_key()
    {
        var port = PortFinder.GetRandomPort();
        var options = new FileCacheOptions
        {
            TtlSeconds = 100,
            Region = "europe-central",
            Header = "Authorization",
        };
        var configuration = GivenFileConfiguration(port, options);
        var headerExpires = "Expires";

        // Add to cache
        this.Given(x => x.GivenThereIsAServiceRunningOn(port, HttpStatusCode.OK, Hello_from_Laura, headerExpires, options.TtlSeconds))
            .And(x => GivenThereIsAConfiguration(configuration))
            .And(x => GivenOcelotIsRunningWithCacheManager())
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))

            // Read from cache
            .Given(x => x.GivenTheServiceNowReturns(port, HttpStatusCode.OK, Hello_from_Tom, headerExpires, options.TtlSeconds / 2))
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Laura))
            .And(x => ThenTheContentLengthIs(Hello_from_Laura.Length))

            // Clean cache by the header and cache new content
            .Given(x => x.GivenTheServiceNowReturns(port, HttpStatusCode.OK, Hello_from_Tom, headerExpires, -1))
            .And(x => GivenIAddAHeader(options.Header, "123"))
            .When(x => WhenIGetUrlOnTheApiGateway("/"))
            .Then(x => ThenTheStatusCodeShouldBe(HttpStatusCode.OK))
            .And(x => ThenTheResponseBodyShouldBe(Hello_from_Tom))
            .And(x => ThenTheContentLengthIs(Hello_from_Tom.Length))
            .BDDfy();
    }

    private FileConfiguration GivenFileConfiguration(int port, FileCacheOptions cacheOptions, bool asGlobalConfig = false)
    {
        var r = GivenRoute(port) as FileRoute;
        r!.CacheOptions = asGlobalConfig ? new() { TtlSeconds = cacheOptions.TtlSeconds } : cacheOptions;
        var c = GivenConfiguration(r) as FileConfiguration;
        c!.GlobalConfiguration = !asGlobalConfig ? null :
            new()
            {
                CacheOptions = new(cacheOptions),
            };
        return c;
    }

    private Task<int> GivenOcelotIsRunningWithCacheManager()
        => GivenOcelotIsRunningWithCacheManager(false);
    private Task<int> GivenOcelotIsRunningWithCacheManager(bool withJsonSerializer)
        => GivenOcelotIsRunningAsync(WithBasicConfiguration,
            s => s.AddOcelot()
                .AddCacheManager(x => _ = withJsonSerializer
                    ? x.WithJsonSerializer().WithHandle(typeof(InMemoryJsonHandle<>))
                    : x.WithDictionaryHandle()),
            WithUseOcelot);

    private static void GivenTheCacheExpires()
    {
        Thread.Sleep(1000);
    }

    private void GivenTheServiceNowReturns(int port, HttpStatusCode statusCode, string responseBody, string key, object value)
    {
        handler.Dispose();
        GivenThereIsAServiceRunningOn(port, statusCode, responseBody, key, value);
    }

    private void GivenThereIsAServiceRunningOn(int port, HttpStatusCode statusCode, string responseBody, string key, object value)
    {
        handler.GivenThereIsAServiceRunningOn(port, context =>
        {
            if (!string.IsNullOrEmpty(key) && value != null)
            {
                context.Response.Headers.Append(key, value.ToString());
            }

            context.Response.StatusCode = (int)statusCode;
            return context.Response.WriteAsync(responseBody);
        });
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "xUnit1013:Public method should be marked as test", Justification = "Steps")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0079:Remove unnecessary suppression", Justification = "Steps")]
    public void GivenThereIsAnEchoServiceRunningOn(int port)
    {
        handler.GivenThereIsAServiceRunningOn(port, async context =>
        {
            using var streamReader = new StreamReader(context.Request.Body);
            var requestBody = await streamReader.ReadToEndAsync();
            _counter++;
            context.Response.StatusCode = (int)HttpStatusCode.OK;
            await context.Response.WriteAsync(requestBody);
        });
    }

    private void ThenTheCounterValueShouldBe(int expected)
    {
        Assert.Equal(expected, _counter);
    }

    public static (string TestBody1String, string TestBody2String) TestBodiesFactory()
    {
        var testBody1 = new TestBody
        {
            Age = 19,
            Email = "tom@ocelot.net",
            FirstName = "Tom",
            LastName = "Test",
        };

        var testBody1String = JsonSerializer.Serialize(testBody1);

        var testBody2 = new TestBody
        {
            Age = 25,
            Email = "laura@ocelot.net",
            FirstName = "Laura",
            LastName = "Test",
        };

        var testBody2String = JsonSerializer.Serialize(testBody2);

        return (testBody1String, testBody2String);
    }
}

public class TestBody
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public int Age { get; set; }
}
