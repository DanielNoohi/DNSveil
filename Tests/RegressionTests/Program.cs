using System.Net;
using System.Net.Sockets;
using SecureDNSClient.GeoHide;

if (args.Length > 0 && args[0] == "--fixture")
{
    if (args[1] == "echo")
    {
        Console.WriteLine(args[2]);
        Console.Error.WriteLine("diagnostic");
        return 7;
    }
    if (args[1] == "flood")
    {
        Console.Write(new string('x', 100_000));
        Console.Error.Write(new string('y', 100_000));
        return 0;
    }
    File.WriteAllText(args[2] + ".writing", Environment.ProcessId.ToString());
    File.Move(args[2] + ".writing", args[2]);
    await Task.Delay(TimeSpan.FromMinutes(1));
    return 0;
}

int failures = 0;
void Check(bool condition, string name)
{
    Console.WriteLine($"{(condition ? "PASS" : "FAIL")}: {name}");
    if (!condition) failures++;
}

Check(!WarpCli.EnumerateEndpointCandidates(maxCount: 0).Any(), "Zero candidate limit returns no endpoints");
Check(!WarpCli.EnumerateEndpointCandidates(maxCount: -1).Any(), "Negative candidate limit returns no endpoints");
Check(WarpCli.EnumerateEndpointCandidates(maxCount: 3).Count() == 3, "Positive candidate limit is respected");

// Local listeners only: no WARP commands or network configuration changes.
var listeners = Enumerable.Range(0, 5).Select(_ => new TcpListener(IPAddress.Loopback, 0)).ToArray();
try
{
    foreach (var listener in listeners) listener.Start();
    var endpoints = listeners.Select(l => $"127.0.0.1:{((IPEndPoint)l.LocalEndpoint).Port}").ToList();
    var one = await WarpCli.FilterReachableEndpointsAsync(endpoints, "MASQUE", null, default, take: 1);
    Check(one.Count == 1, "Reachability scan honors take=1");
    var zero = await WarpCli.FilterReachableEndpointsAsync(endpoints, "MASQUE", null, default, take: 0);
    Check(zero.Count == 0, "Reachability scan honors take=0");
}
finally
{
    foreach (var listener in listeners) listener.Stop();
}

// Reserve 443 without listening so the fallback is deterministic. If either port
// is already in use, fail visibly rather than testing against an unrelated service.
using (var closedPort = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
{
    closedPort.ExclusiveAddressUse = true;
    closedPort.Bind(new IPEndPoint(IPAddress.Loopback, 443));
    var fallback = new TcpListener(IPAddress.Loopback, 8443);
    fallback.Server.ExclusiveAddressUse = true;
    try
    {
        fallback.Start();
        var reachable = await WarpCli.FilterReachableEndpointsAsync(
            new[] { "127.0.0.1:443" }, "MASQUE", null, default, timeoutMs: 500);
        Check(reachable.SequenceEqual(new[] { "127.0.0.1:8443" }), "Fallback returns the port that actually responded");
    }
    finally { fallback.Stop(); }
}

await ReliabilityChecks.RunAsync(Check);
await RegionalChecks.RunAsync(Check);
return failures == 0 ? 0 : 1;
