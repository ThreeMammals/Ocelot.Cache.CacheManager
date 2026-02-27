using Ocelot.Configuration.File;
using Ocelot.Infrastructure.Extensions;
using Ocelot.Testing;
using System.Runtime.CompilerServices;

namespace Ocelot.Cache.CacheManager.UnitTests;

public class UnitTest : Unit
{
    protected static FileRouteBox<FileRoute> Box(FileRoute route) => new(route);
    protected string TestName([CallerMemberName] string? testName = null) => testName.IfEmpty(TestID);

    protected static bool IsCiCd() => IsRunningInGitHubActions();
    protected static bool IsRunningInGitHubActions()
        => Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true";
}
