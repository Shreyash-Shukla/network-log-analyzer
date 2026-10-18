using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using BandwidthProbe.Core;

const int TransferBytes = 100 * 1024 * 1024;
if (args.Length >= 3 && args[0] == "--client")
{
    bool ipv6Client = args.Contains("--ipv6");
    using var client = new TcpClient(ipv6Client ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
    await client.ConnectAsync(ipv6Client ? IPAddress.IPv6Loopback : IPAddress.Loopback, int.Parse(args[1]));
    var stream = client.GetStream();
    var buffer = new byte[128 * 1024];
    long received = 0;
    while (received < long.Parse(args[2]))
    {
        int read = await stream.ReadAsync(buffer);
        if (read == 0) throw new EndOfStreamException();
        received += read;
    }
    return;
}
if (args.Length >= 3 && args[0] == "--udp-client")
{
    using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, int.Parse(args[1])));
    client.Client.ReceiveBufferSize = 16 * 1024 * 1024;
    int received = 0;
    int packets = 0;
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
    while (received < int.Parse(args[2]))
    {
        var packet = await client.ReceiveAsync(timeout.Token);
        received += packet.Buffer.Length;
        packets++;
        if (packets % 128 == 0 || received >= int.Parse(args[2]))
            await client.SendAsync(new byte[1], packet.RemoteEndPoint);
    }
    return;
}
if (args.Length == 3 && args[0] == "--traffic-server")
{
    using var listener = new TcpListener(IPAddress.Loopback, int.Parse(args[1]));
    listener.Start();
    Console.WriteLine("READY");
    Console.Out.Flush();
    using var server = await listener.AcceptTcpClientAsync();
    var stream = server.GetStream();
    byte[] batch = new byte[1_250_000];
    long remaining = long.Parse(args[2]);
    while (remaining > 0)
    {
        int count = (int)Math.Min(batch.Length, remaining);
        await stream.WriteAsync(batch.AsMemory(0, count));
        remaining -= count;
        await Task.Delay(100);
    }
    server.Client.Shutdown(SocketShutdown.Send);
    return;
}

var results = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "results"));
using var collector = new EtwBandwidthCollector(results);
using var self = Process.GetCurrentProcess();
var cpuBefore = self.TotalProcessorTime;
var runClock = Stopwatch.StartNew();
long eventsBeforeMeasurement = 0;
bool transfer = args.Contains("--transfer-test");
bool concurrent = args.Contains("--concurrent-test");
bool idle = args.Contains("--idle-test");
bool warmIdle = args.Contains("--warm-idle-test");
bool longIdle = args.Contains("--long-idle-test");
bool extendedIdle = args.Contains("--extended-idle-test");
bool overhead = args.Contains("--overhead-test");
bool stress = args.Contains("--stress-test");
bool ipv6 = args.Contains("--ipv6");
bool udp = args.Contains("--udp");
var output = new Dictionary<string, object?>
{
    ["schema"] = 1,
    ["kind"] = extendedIdle ? "extended-idle-30min" : stress ? "stress-100mbps-10min" : overhead ? "overhead-100mbps" : longIdle ? "warm-idle-120s" : warmIdle ? "warm-idle-30s" : idle ? "idle-30s" : concurrent ? "concurrent-loopback-transfer" : transfer ? (udp ? "udp-loopback-transfer" : ipv6 ? "ipv6-loopback-transfer" : "loopback-transfer") : "permission-smoke",
    ["timeUtc"] = DateTime.UtcNow,
    ["user"] = Environment.UserName,
    ["isElevated"] = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
        .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)
};
try
{
    collector.Start();
    if (overhead || stress)
    {
        long targetBytes = stress ? 7_500_000_000L : 375_000_000L; // 100 megabits/sec.
        using var portHolder = new TcpListener(IPAddress.Loopback, 0);
        portHolder.Start();
        int port = ((IPEndPoint)portHolder.LocalEndpoint).Port;
        portHolder.Stop();
        var dll = Assembly.GetExecutingAssembly().Location;
        using var server = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"\"{dll}\" --traffic-server {port} {targetBytes}")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })
            ?? throw new InvalidOperationException("Traffic server failed.");
        if (await server.StandardOutput.ReadLineAsync() != "READY") throw new InvalidOperationException("Traffic server was not ready.");
        using var client = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"\"{dll}\" --client {port} {targetBytes}")
            { UseShellExecute = false, CreateNoWindow = true })
            ?? throw new InvalidOperationException("Traffic client failed.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(stress ? 720 : 90));
        await Task.WhenAll(server.WaitForExitAsync(timeout.Token), client.WaitForExitAsync(timeout.Token));
        if (server.ExitCode != 0 || client.ExitCode != 0) throw new InvalidOperationException("Traffic generator failed.");
        await Task.Delay(3000);
        output["expectedBytes"] = targetBytes;
        output["serverPid"] = server.Id;
        output["clientPid"] = client.Id;
    }
    else if (extendedIdle)
    {
        await Task.Delay(TimeSpan.FromSeconds(10));
        var samples = new List<object>();
        var priorCpu = self.TotalProcessorTime;
        var priorEvents = collector.Snapshot().EventsSeen;
        var sampleClock = Stopwatch.StartNew();
        cpuBefore = priorCpu;
        eventsBeforeMeasurement = priorEvents;
        runClock.Restart();
        for (int i = 0; i < 15; i++)
        {
            await Task.Delay(TimeSpan.FromMinutes(2));
            var snap = collector.Snapshot();
            self.Refresh();
            var cpu = self.TotalProcessorTime;
            var seconds = sampleClock.Elapsed.TotalSeconds;
            samples.Add(new
            {
                window = i + 1,
                elapsedSeconds = seconds,
                cpuPercentOfOneCore = 100 * (cpu - priorCpu).TotalSeconds / seconds,
                eventsPerSecond = (snap.EventsSeen - priorEvents) / seconds,
                privateBytes = self.PrivateMemorySize64,
                snap.EventsLost,
                snap.ParseFailures,
                snap.ExportDrops,
                snap.DataGap
            });
            priorCpu = cpu;
            priorEvents = snap.EventsSeen;
            sampleClock.Restart();
        }
        output["idleSamples"] = samples;
    }
    else if (warmIdle || longIdle)
    {
        await Task.Delay(TimeSpan.FromSeconds(longIdle ? 10 : 5));
        eventsBeforeMeasurement = collector.Snapshot().EventsSeen;
        cpuBefore = self.TotalProcessorTime;
        runClock.Restart();
        await Task.Delay(TimeSpan.FromSeconds(longIdle ? 120 : 30));
    }
    else if (idle) await Task.Delay(TimeSpan.FromSeconds(30));
    else if (concurrent)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dll = Assembly.GetExecutingAssembly().Location;
        using var child1 = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"\"{dll}\" --client {port} {TransferBytes}")
            { UseShellExecute = false, CreateNoWindow = true }) ?? throw new InvalidOperationException("Client 1 failed.");
        using var child2 = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"\"{dll}\" --client {port} {TransferBytes}")
            { UseShellExecute = false, CreateNoWindow = true }) ?? throw new InvalidOperationException("Client 2 failed.");
        using var socket1 = await listener.AcceptTcpClientAsync();
        using var socket2 = await listener.AcceptTcpClientAsync();
        await Task.Delay(1000);
        static async Task Send100Mb(TcpClient socket)
        {
            byte[] chunk = new byte[128 * 1024];
            var stream = socket.GetStream();
            for (int sent = 0; sent < TransferBytes; sent += chunk.Length) await stream.WriteAsync(chunk);
            socket.Client.Shutdown(SocketShutdown.Send);
        }
        await Task.WhenAll(Send100Mb(socket1), Send100Mb(socket2));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        await Task.WhenAll(child1.WaitForExitAsync(timeout.Token), child2.WaitForExitAsync(timeout.Token));
        if (child1.ExitCode != 0 || child2.ExitCode != 0) throw new InvalidOperationException("A concurrent client failed.");
        await Task.Delay(3000);
        output["expectedBytesPerClient"] = TransferBytes;
        output["serverPid"] = Environment.ProcessId;
        output["clientPids"] = new[] { child1.Id, child2.Id };
    }
    else if (transfer)
    {
        using var listener = new TcpListener(ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        if (udp) listener.Stop();
        var dll = Assembly.GetExecutingAssembly().Location;
        using var child = Process.Start(new ProcessStartInfo
        {
            FileName = Environment.ProcessPath!,
            Arguments = $"\"{dll}\" {(udp ? "--udp-client" : "--client")} {port} {TransferBytes} {(ipv6 ? "--ipv6" : "")}",
            UseShellExecute = false,
            CreateNoWindow = true
        }) ?? throw new InvalidOperationException("Could not launch test client.");
        if (udp)
        {
            using var sender = new UdpClient(AddressFamily.InterNetwork);
            byte[] packet = new byte[8192];
            int sent = 0;
            int packets = 0;
            await Task.Delay(1000);
            while (sent < TransferBytes)
            {
                int count = Math.Min(packet.Length, TransferBytes - sent);
                await sender.SendAsync(packet.AsMemory(0, count), new IPEndPoint(IPAddress.Loopback, port));
                sent += count;
                packets++;
                if (packets % 128 == 0 || sent >= TransferBytes)
                {
                    using var ackTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                    await sender.ReceiveAsync(ackTimeout.Token);
                }
            }
        }
        else
        {
            using var server = await listener.AcceptTcpClientAsync();
            await Task.Delay(1000);
            byte[] chunk = new byte[128 * 1024];
            var stream = server.GetStream();
            int sent = 0;
            while (sent < TransferBytes)
            {
                int count = Math.Min(chunk.Length, TransferBytes - sent);
                await stream.WriteAsync(chunk.AsMemory(0, count));
                sent += count;
            }
            server.Client.Shutdown(SocketShutdown.Send);
        }
        using var childTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        await child.WaitForExitAsync(childTimeout.Token);
        if (child.ExitCode != 0) throw new InvalidOperationException($"Test client exit: {child.ExitCode}");
        await Task.Delay(3000); // Let ETW deliver buffered events.
        output["expectedBytes"] = TransferBytes;
        output["serverPid"] = Environment.ProcessId;
        output["clientPid"] = child.Id;
    }
    else await Task.Delay(TimeSpan.FromSeconds(5));
    var snapshot = collector.Snapshot();
    output["started"] = true;
    output["eventsSeen"] = snapshot.EventsSeen;
    output["eventsLost"] = snapshot.EventsLost;
    output["parseFailures"] = snapshot.ParseFailures;
    output["exportDrops"] = snapshot.ExportDrops;
    output["appCount"] = snapshot.Apps.Count;
    output["adapterCount"] = snapshot.Adapters.Count;
    output["status"] = snapshot.Status;
    output["dataGap"] = snapshot.DataGap;
    output["sessionFileAvailable"] = collector.SessionFile is not null;
    output["elapsedSeconds"] = runClock.Elapsed.TotalSeconds;
    output["collectorProcessCpuSeconds"] = (self.TotalProcessorTime - cpuBefore).TotalSeconds;
    output["collectorCpuPercentOfOneCore"] = 100 * (self.TotalProcessorTime - cpuBefore).TotalSeconds / Math.Max(0.001, runClock.Elapsed.TotalSeconds);
    output["collectorProcessPrivateBytes"] = self.PrivateMemorySize64;
    output["eventsPerSecond"] = (snapshot.EventsSeen - eventsBeforeMeasurement) / Math.Max(0.001, runClock.Elapsed.TotalSeconds);
    long observedBytes = snapshot.Apps.Sum(x => x.DownloadBytes + x.UploadBytes);
    long unknownSystemBytes = snapshot.Apps.Where(x => x.Name.StartsWith("Unknown process") ||
        x.Name.Equals("System", StringComparison.OrdinalIgnoreCase) ||
        x.Name.StartsWith("Windows services (svchost.exe)")).Sum(x => x.DownloadBytes + x.UploadBytes);
    output["observedBytes"] = observedBytes;
    output["unknownSystemBytes"] = unknownSystemBytes;
    output["unknownSystemPercent"] = observedBytes == 0 ? 0 : 100.0 * unknownSystemBytes / observedBytes;
    if (overhead || stress)
    {
        var serverUsage = snapshot.Apps.FirstOrDefault(x => x.Pid == (int)output["serverPid"]!);
        var clientUsage = snapshot.Apps.FirstOrDefault(x => x.Pid == (int)output["clientPid"]!);
        output["serverUploadBytes"] = serverUsage?.UploadBytes ?? 0;
        output["clientDownloadBytes"] = clientUsage?.DownloadBytes ?? 0;
        output["appTotals"] = snapshot.Apps;
    }
    else if (concurrent)
    {
        var pids = (int[])output["clientPids"]!;
        var serverUsage = snapshot.Apps.FirstOrDefault(x => x.Pid == Environment.ProcessId);
        var downloads = pids.Select(pid => snapshot.Apps.FirstOrDefault(x => x.Pid == pid)?.DownloadBytes ?? 0).ToArray();
        output["serverUploadBytes"] = serverUsage?.UploadBytes ?? 0;
        output["clientDownloadBytes"] = downloads;
        output["serverRatio"] = (serverUsage?.UploadBytes ?? 0) / (double)(2 * TransferBytes);
        output["clientRatios"] = downloads.Select(x => x / (double)TransferBytes).ToArray();
        output["appTotals"] = snapshot.Apps;
    }
    else if (transfer)
    {
        var serverUsage = snapshot.Apps.FirstOrDefault(x => x.Pid == Environment.ProcessId);
        var clientUsage = snapshot.Apps.FirstOrDefault(x => x.Pid == (int)output["clientPid"]!);
        output["serverUploadBytes"] = serverUsage?.UploadBytes ?? 0;
        output["clientDownloadBytes"] = clientUsage?.DownloadBytes ?? 0;
        output["serverRatio"] = (serverUsage?.UploadBytes ?? 0) / (double)TransferBytes;
        output["clientRatio"] = (clientUsage?.DownloadBytes ?? 0) / (double)TransferBytes;
        output["appTotals"] = snapshot.Apps;
    }
}
catch (Exception ex)
{
    output["started"] = false;
    output["errorType"] = ex.GetType().FullName;
    output["error"] = ex.Message;
    var snapshot = collector.Snapshot();
    output["status"] = snapshot.Status;
    output["dataGap"] = snapshot.DataGap;
    output["sessionFileAvailable"] = collector.SessionFile is not null;
}
finally { collector.Pause(); }
Directory.CreateDirectory(results);
var report = Path.Combine(results, $"{(extendedIdle ? "extended-idle-30min" : stress ? "stress-100mbps-10min" : overhead ? "overhead-100mbps" : longIdle ? "warm-idle-120s" : warmIdle ? "warm-idle-30s" : idle ? "idle-30s" : concurrent ? "concurrent-loopback-transfer" : transfer ? (udp ? "udp-loopback-transfer" : ipv6 ? "ipv6-loopback-transfer" : "loopback-transfer") : "permission-smoke")}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
File.WriteAllText(report, JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine(report);
Console.WriteLine(JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));
