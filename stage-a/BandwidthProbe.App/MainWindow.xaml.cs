using System.Windows;
using System.Windows.Threading;
using BandwidthProbe.Core;
using Microsoft.Win32;

namespace BandwidthProbe.App;

public partial class MainWindow : Window
{
    private readonly IBandwidthCollector _collector;
    private readonly DispatcherTimer _timer;
    private string? _startError;

    public MainWindow()
    {
        InitializeComponent();
        var results = ResultsDirectory();
        _collector = new EtwBandwidthCollector(results);
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
        Closed += (_, _) => _collector.Dispose();
        Refresh();
    }

    private void Start_Click(object sender, RoutedEventArgs e)
    {
        _startError = null;
        try { _collector.Start(); }
        catch (Exception ex)
        {
            _startError = ex.Message;
            Refresh();
            return;
        }
        Refresh();
    }

    private void Pause_Click(object sender, RoutedEventArgs e) { _collector.Pause(); Refresh(); }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_collector.SessionFile is null) { MessageBox.Show(this, "Start a session first."); return; }
        var dialog = new SaveFileDialog { Filter = "JSON Lines (*.jsonl)|*.jsonl", FileName = "bandwidth-session.jsonl" };
        if (dialog.ShowDialog(this) != true) return;
        try { _collector.Export(dialog.FileName); Refresh(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed"); }
    }

    private void Refresh()
    {
        BandwidthSnapshot snap;
        try { snap = _collector.Snapshot(); }
        catch (Exception ex) { GapBanner.Visibility = Visibility.Visible; GapText.Text = $"Measurement error: {ex.Message}"; return; }
        StatusText.Text = snap.Status;
        GapBanner.Visibility = snap.DataGap || _startError is not null ? Visibility.Visible : Visibility.Collapsed;
        GapText.Text = _startError is not null
            ? $"Cannot start recording: {_startError}"
            : $"Data gap: numbers may be incomplete. {snap.Status}";
        RateText.Text = $"Download {Format(snap.DownloadBytesPerSecond)}/s    Upload {Format(snap.UploadBytesPerSecond)}/s";
        CounterText.Text = $"Events: {snap.EventsSeen:N0}    Lost: {snap.EventsLost:N0}    Parse failures: {snap.ParseFailures:N0}    Export drops: {snap.ExportDrops:N0}";
        ProcessGrid.ItemsSource = snap.Apps.Select(x => new
        { x.Pid, x.Name, Download = Format(x.DownloadBytes), Upload = Format(x.UploadBytes) }).ToArray();
        AdapterGrid.ItemsSource = snap.Adapters.Select(x => new
        { x.Name, x.Type, Download = Format(x.DownloadBytes), Upload = Format(x.UploadBytes) }).ToArray();
        StartButton.IsEnabled = !snap.Running;
        PauseButton.IsEnabled = snap.Running;
        ExportButton.IsEnabled = _collector.SessionFile is not null;
    }

    private static string Format(double bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        int unit = 0;
        while (bytes >= 1024 && unit < units.Length - 1) { bytes /= 1024; unit++; }
        return $"{bytes:0.##} {units[unit]}";
    }

    private static string ResultsDirectory()
    {
        for (var dir = new System.IO.DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (System.IO.File.Exists(System.IO.Path.Combine(dir.FullName, "stage-a", "BandwidthProbe.slnx")))
                return System.IO.Path.Combine(dir.FullName, "results");
        return System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BandwidthProbe", "StageAResults");
    }
}
