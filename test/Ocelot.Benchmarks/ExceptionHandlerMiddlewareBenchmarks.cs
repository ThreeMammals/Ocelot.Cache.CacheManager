using System;
using System.Collections.Generic;
using System.IO;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Ocelot.Configuration.File;
using Ocelot.DownstreamRouteFinder.UrlMatcher;
using Ocelot.Middleware;
using Ocelot.DependencyInjection;
using System.Net.Http;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes.Jobs;
using Ocelot.Configuration.Repository;
using Ocelot.Infrastructure.RequestData;
using Ocelot.Logging;
using Ocelot.Errors.Middleware;
using Microsoft.Extensions.DependencyInjection;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Validators;

namespace Ocelot.Benchmarks
{
    [SimpleJob(launchCount: 1, warmupCount: 2, targetCount: 5)]
    [Config(typeof(ExceptionHandlerMiddlewareBenchmarks))]
    public class ExceptionHandlerMiddlewareBenchmarks : ManualConfig
    {
        private ExceptionHandlerMiddleware _middleware;
        private DownstreamContext _downstreamContext;
        private OcelotRequestDelegate _next;

        public ExceptionHandlerMiddlewareBenchmarks()
        {
            Add(StatisticColumn.AllStatistics);
            Add(MemoryDiagnoser.Default);
            Add(BaselineValidator.FailOnError);
        }

        [GlobalSetup]
        public void SetUp()
        {
            var serviceCollection = new ServiceCollection();
            var config = new ConfigurationRoot(new List<IConfigurationProvider>());
            var builder = new OcelotBuilder(serviceCollection, config);
            var services = serviceCollection.BuildServiceProvider();
            var loggerFactory = services.GetService<IOcelotLoggerFactory>();
            var configRepo = services.GetService<IInternalConfigurationRepository>();
            var repo = services.GetService<IRequestScopedDataRepository>();
            _next = async context => {
                await Task.CompletedTask;
                throw new Exception("BOOM");
            };
            _middleware = new ExceptionHandlerMiddleware(_next, loggerFactory, configRepo, repo);
            _downstreamContext = new DownstreamContext(new DefaultHttpContext());
        }

        [Benchmark(Baseline = true)]
        public async Task Baseline()
        {
            await _middleware.Invoke(_downstreamContext);
        }
    }
}
