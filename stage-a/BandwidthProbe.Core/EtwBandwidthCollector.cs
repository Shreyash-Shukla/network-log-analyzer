using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace BandwidthProbe.Core;

public sealed class EtwBandwidthCollector : IBandwidthCollector
{
    private static readonly Guid Provider = new("7dd42a49-5329-4832-8dfd-43d979153a88");
    private static readonly Guid ProcessProvider = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
    private readonly object _gate = new();
    private readonly Dictionary<string, MutableUsage> _apps = [];
    private readonly Dictionary<int, MutableUsage> _activePids = [];
    private readonly Dictionary<int, MutableUsage> _processStarts = [];
    private readonly Dictionary<string, AdapterCounter> _adapters = [];
    private IReadOnlyList<AdapterUsage>? _pausedAdapters;
    private readonly string _resultsDirectory;
    private TraceEventSession? _session;
    private Task? _reader;
    private Channel<string>? _lines;
    private Task? _writer;
    private StreamWriter? _stream;
    private Stopwatch _rateClock = Stopwatch.StartNew();
    private long _lastDownload;
    private long _lastUpload;
    private long _eventsSeen;
    private long _lastEventsLost;
    private long _parseFailures;
    private long _exportDrops;
    private bool _gap;
    private string _status = "Paused";

    public EtwBandwidthCollector(string resultsDirectory) => _resultsDirectory = resultsDirectory;
    public bool IsRunning { get { lock (_gate) return _session is not null; } }
    public string Status { get { lock (_gate) return _status; } }
    public string? SessionFile { get; private set; }

    public void Start()
    {
        lock (_gate)
        {
            if (_session is not null) return;
            _stream?.Dispose();
            _stream = null;
            _apps.Clear();
            _activePids.Clear();
            _processStarts.Clear();
            _adapters.Clear();
            _pausedAdapters = null;
            _eventsSeen = _lastEventsLost = _parseFailures = _exportDrops = 0;
            _lastDownload = _lastUpload = 0;
            _gap = false;
            Directory.CreateDirectory(_resultsDirectory);
            SessionFile = Path.Combine(_resultsDirectory, $"session-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.jsonl");
            _stream = new StreamWriter(new FileStream(SessionFile, FileMode.CreateNew, FileAccess.Write, FileShare.Read));
            _lines = Channel.CreateBounded<string>(new BoundedChannelOptions(16384)
            { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
            _writer = Task.Run(WriteLinesAsync);
            try
            {
                // A unique name prevents a collision with tools that use their own ETW sessions.
                _session = new TraceEventSession($"BandwidthProbe.StageA.{Environment.ProcessId}.{Guid.NewGuid():N}");
                _session.StopOnDispose = true;
                _session.Source.Dynamic.All += OnEvent;
                _session.EnableProvider(Provider, TraceEventLevel.Informational, 0x30);
                _session.EnableProvider(ProcessProvider, TraceEventLevel.Informational, 0x10);
                var activeSession = _session;
                _reader = Task.Run(() =>
                {
                    try { activeSession.Source.Process(); }
                    catch (Exception ex)
                    {
                        lock (_gate) { _gap = true; _status = $"Collector stopped: {ex.Message}"; }
                    }
                    finally
                    {
                        lock (_gate)
                        {
                            if (ReferenceEquals(_session, activeSession))
                            {
                                _gap = true;
                                _status = "Collector stopped unexpectedly";
                            }
                        }
                    }
                });
                _status = "Recording";
                _rateClock.Restart();
                CaptureAdapterBaseline();
            }
            catch (Exception ex)
            {
                _gap = true;
                _status = $"Cannot start recording: {ex.Message}";
                _session?.Dispose();
                _session = null;
                _lines.Writer.TryComplete();
                // A failed start did not create a usable capture to export.
                SessionFile = null;
                throw;
            }
        }
    }

    private void OnEvent(TraceEvent data)
    {
        if (data.ProviderGuid == ProcessProvider)
        {
            OnProcessEvent(data);
            return;
        }
        if (data.ProviderGuid != Provider) return;
        try
        {
            var opcode = (int)data.Opcode;
            // Data events only: TCP send/receive (10/11), UDP send/receive (42/43).
            bool upload = opcode is 10 or 42;
            bool download = opcode is 11 or 43;
            if (!upload && !download) return;
            var pidValue = data.PayloadByName("PID");
            var sizeValue = data.PayloadByName("size");
            if (pidValue is null || sizeValue is null) { Interlocked.Increment(ref _parseFailures); return; }
            var pid = Convert.ToInt32(pidValue, CultureInfo.InvariantCulture);
            var bytes = Convert.ToInt64(sizeValue, CultureInfo.InvariantCulture);
            if (bytes < 0) { Interlocked.Increment(ref _parseFailures); return; }
            var timestamp = data.TimeStamp.ToUniversalTime();
            string appName;
            DateTime? processStartUtc;
            bool dataGap;
            lock (_gate)
            {
                if (!_activePids.TryGetValue(pid, out var app) || timestamp - app.LastCheckedUtc >= TimeSpan.FromSeconds(2))
                {
                    var resolved = ResolveWithCache(pid);
                    if (app is null || app.StartUtc != resolved.StartUtc || app.Name != resolved.Name)
                    {
                        app = resolved;
                        _apps[$"{pid}:{app.StartUtc?.Ticks ?? timestamp.Ticks}"] = app;
                        _activePids[pid] = app;
                    }
                    app.LastCheckedUtc = timestamp;
                }
                if (download) app.Download += bytes; else app.Upload += bytes;
                appName = app.Name;
                processStartUtc = app.StartUtc;
                dataGap = _gap;
            }
            Interlocked.Increment(ref _eventsSeen);
            var line = JsonSerializer.Serialize(new { schema = 1, kind = "network-event", timestampUtc = timestamp,
                pid, processStartUtc, process = appName,
                attribution = appName.StartsWith("Unknown process") ? "unknown" : appName == "System" ? "system" :
                    appName.StartsWith("Windows services") ? "shared-service-host" : "process",
                direction = download ? "download" : "upload", bytes, dataGap,
                adapterId = (string?)null, adapterType = (string?)null,
                eventName = data.EventName, opcode });
            if (_lines?.Writer.TryWrite(line) != true) { Interlocked.Increment(ref _exportDrops); lock (_gate) _gap = true; }
        }
        catch { Interlocked.Increment(ref _parseFailures); lock (_gate) _gap = true; }
    }

    private void OnProcessEvent(TraceEvent data)
    {
        int eventId = (int)data.ID;
        if (eventId is not (1 or 2)) return;
        try
        {
            var pidValue = Payload(data, "ProcessID", "ProcessId", "PID");
            if (pidValue is null) return;
            int pid = Convert.ToInt32(pidValue, CultureInfo.InvariantCulture);
            var image = Payload(data, "ImageName", "ImageFileName")?.ToString();
            if (eventId == 1)
            {
                var resolved = Resolve(pid);
                string name = !string.IsNullOrWhiteSpace(image) ? FriendlyName(Path.GetFileNameWithoutExtension(image)) : resolved.Name;
                var entry = new MutableUsage(pid, name, data.TimeStamp.ToUniversalTime());
                lock (_gate) _processStarts[pid] = entry;
                if (_lines?.Writer.TryWrite(JsonSerializer.Serialize(new { schema = 1, kind = "process-start",
                    timestampUtc = entry.StartUtc, pid, process = name })) != true)
                { Interlocked.Increment(ref _exportDrops); lock (_gate) _gap = true; }
            }
            else if (!string.IsNullOrWhiteSpace(image))
            {
                string name = FriendlyName(Path.GetFileNameWithoutExtension(image));
                lock (_gate)
                {
                    if (_activePids.TryGetValue(pid, out var active) && active.Name.StartsWith("Unknown process")) active.Name = name;
                    if (_processStarts.TryGetValue(pid, out var started)) started.Name = name;
                }
            }
        }
        catch { /* Network events can still be counted as Unknown. */ }
    }

    private static object? Payload(TraceEvent data, params string[] names)
    {
        foreach (var name in names)
        {
            try { var value = data.PayloadByName(name); if (value is not null) return value; }
            catch { }
        }
        return null;
    }

    private static string FriendlyName(string name) => name.Equals("svchost", StringComparison.OrdinalIgnoreCase)
        ? "Windows services (svchost.exe)" : name;

    private MutableUsage ResolveWithCache(int pid)
    {
        if (_processStarts.TryGetValue(pid, out var started))
            return new MutableUsage(pid, started.Name, started.StartUtc);
        return Resolve(pid);
    }

    private static MutableUsage Resolve(int pid)
    {
        if (pid is 0 or 4) return new(pid, "System", null);
        try
        {
            using var process = Process.GetProcessById(pid);
            DateTime? started = null;
            try { started = process.StartTime.ToUniversalTime(); } catch { }
            string name = process.ProcessName.Equals("svchost", StringComparison.OrdinalIgnoreCase)
                ? "Windows services (svchost.exe)" : process.ProcessName;
            return new(pid, name, started);
        }
        catch { return new(pid, $"Unknown process (PID {pid})", null); }
    }

    private void CaptureAdapterBaseline()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var stats = nic.GetIPStatistics();
                _adapters[nic.Id] = new(nic.Name, nic.NetworkInterfaceType.ToString(), stats.BytesReceived, stats.BytesSent);
            }
            catch { _gap = true; }
        }
    }

    public BandwidthSnapshot Snapshot()
    {
        lock (_gate)
        {
            long down = _apps.Values.Sum(x => x.Download), up = _apps.Values.Sum(x => x.Upload);
            double seconds = Math.Max(_rateClock.Elapsed.TotalSeconds, 0.001);
            double downRate = _session is null ? 0 : Math.Max(0, down - _lastDownload) / seconds;
            double upRate = _session is null ? 0 : Math.Max(0, up - _lastUpload) / seconds;
            _lastDownload = down; _lastUpload = up; _rateClock.Restart();
            var adapters = new List<AdapterUsage>();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (_session is null)
                    {
                        if (_pausedAdapters is null) adapters.Add(new(nic.Name, nic.NetworkInterfaceType.ToString(), 0, 0));
                        continue;
                    }
                    var stats = nic.GetIPStatistics();
                    if (!_adapters.TryGetValue(nic.Id, out var baseline))
                    {
                        _adapters[nic.Id] = new(nic.Name, nic.NetworkInterfaceType.ToString(), stats.BytesReceived, stats.BytesSent);
                        _gap = true;
                        baseline = _adapters[nic.Id];
                    }
                    if (stats.BytesReceived < baseline.Download || stats.BytesSent < baseline.Upload) _gap = true;
                    adapters.Add(new(nic.Name, nic.NetworkInterfaceType.ToString(),
                        Math.Max(0, stats.BytesReceived - baseline.Download), Math.Max(0, stats.BytesSent - baseline.Upload)));
                }
                catch { _gap = true; }
            }
            if (_session is not null && _adapters.Keys.Except(NetworkInterface.GetAllNetworkInterfaces().Select(x => x.Id)).Any()) _gap = true;
            if (_session is null && _pausedAdapters is not null) adapters = [.. _pausedAdapters];
            long lost = 0;
            try { lost = _session?.EventsLost ?? _lastEventsLost; } catch { _gap = true; }
            if (lost > 0) _gap = true;
            var apps = _apps.Values.OrderByDescending(x => x.Download + x.Upload)
                .Select(x => new AppUsage(x.Pid, x.Name, x.StartUtc, x.Download, x.Upload)).ToArray();
            return new(DateTime.UtcNow, _session is not null, _status, _gap,
                Interlocked.Read(ref _eventsSeen), lost, Interlocked.Read(ref _parseFailures),
                Interlocked.Read(ref _exportDrops), downRate, upRate, apps, adapters);
        }
    }

    public void Pause()
    {
        IReadOnlyList<AdapterUsage>? finalAdapters = IsRunning ? Snapshot().Adapters.ToArray() : null;
        TraceEventSession? session;
        lock (_gate)
        {
            session = _session;
            _session = null;
            if (finalAdapters is not null) _pausedAdapters = finalAdapters;
            if (_status == "Recording") _status = "Paused";
        }
        if (session is null) return;
        long lost = 0;
        try { lost = session.EventsLost; } catch { lock (_gate) _gap = true; }
        lock (_gate) _lastEventsLost = lost;
        try { session.Dispose(); }
        catch (Exception ex) { lock (_gate) { _gap = true; _status = $"Collector stop failed: {ex.Message}"; } }
        _lines?.Writer.TryComplete();
        try
        {
            if (_reader?.Wait(TimeSpan.FromSeconds(3)) == false || _writer?.Wait(TimeSpan.FromSeconds(3)) == false)
                lock (_gate) _gap = true;
        }
        catch { lock (_gate) _gap = true; }
        if (_stream is not null && (_writer?.IsCompleted ?? true))
        {
            try
            {
                _stream.WriteLine(JsonSerializer.Serialize(new { schema = 1, kind = "session-summary",
                    timestampUtc = DateTime.UtcNow, eventsSeen = Interlocked.Read(ref _eventsSeen),
                    eventsLost = lost, parseFailures = Interlocked.Read(ref _parseFailures),
                    exportDrops = Interlocked.Read(ref _exportDrops), dataGap = _gap }));
                _stream.Flush();
            }
            catch (Exception ex) { lock (_gate) { _gap = true; _status = $"Export recording failed: {ex.Message}"; } }
        }
    }

    private async Task WriteLinesAsync()
    {
        if (_stream is null || _lines is null) return;
        try
        {
            await foreach (var line in _lines.Reader.ReadAllAsync()) await _stream.WriteLineAsync(line);
            await _stream.FlushAsync();
        }
        catch (Exception ex) { lock (_gate) { _gap = true; _status = $"Export recording failed: {ex.Message}"; } }
    }

    public void Export(string destination)
    {
        if (SessionFile is null) throw new InvalidOperationException("No session yet.");
        Pause(); // A closed session is a consistent JSONL export.
        File.Copy(SessionFile, destination, overwrite: false);
    }

    public void Dispose()
    {
        Pause();
        _stream?.Dispose();
    }

    private sealed class MutableUsage(int pid, string name, DateTime? startUtc)
    {
        public int Pid { get; } = pid;
        public string Name { get; set; } = name;
        public DateTime? StartUtc { get; } = startUtc;
        public long Download;
        public long Upload;
        public DateTime LastCheckedUtc;
    }
    private sealed record AdapterCounter(string Name, string Type, long Download, long Upload);
}
