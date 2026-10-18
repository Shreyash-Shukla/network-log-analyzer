namespace BandwidthProbe.Core;

public interface IBandwidthCollector : IDisposable
{
    bool IsRunning { get; }
    string Status { get; }
    string? SessionFile { get; }
    void Start();
    void Pause();
    BandwidthSnapshot Snapshot();
    void Export(string destination);
}

public record AppUsage(int Pid, string Name, DateTime? StartUtc, long DownloadBytes, long UploadBytes);
public record AdapterUsage(string Name, string Type, long DownloadBytes, long UploadBytes);
public record BandwidthSnapshot(
    DateTime TimestampUtc, bool Running, string Status, bool DataGap,
    long EventsSeen, long EventsLost, long ParseFailures, long ExportDrops,
    double DownloadBytesPerSecond, double UploadBytesPerSecond,
    IReadOnlyList<AppUsage> Apps, IReadOnlyList<AdapterUsage> Adapters);
