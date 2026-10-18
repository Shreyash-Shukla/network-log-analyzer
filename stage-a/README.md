# Stage A desktop probe

This is a plain Windows measurement test app. It is not the finished product. See [`../PHASE_A_REPORT.md`](../PHASE_A_REPORT.md) for measured results and the current NO-GO decision.

## Projects

- `BandwidthProbe.Core`: UI-free `IBandwidthCollector` and ETW collector.
- `BandwidthProbe.App`: WPF probe window.
- `BandwidthProbe.Validation`: controlled traffic and permission test harness. It is test code, not the product CLI.

## Run locally

Install the .NET 10 SDK, then from this repository run:

```powershell
dotnet build stage-a/BandwidthProbe.slnx
dotnet run --project stage-a/BandwidthProbe.App
```

The window opens without elevation, but this machine denied a normal user permission to start the ETW collector. For actual recording in Stage A, launch the app elevated with Windows' **Run as administrator**. The future release design is an unelevated UI with a narrow privileged collector service; that service is not implemented here. The app creates only its own private ETW session when Start is pressed and stops it when paused or closed.

On this machine, launching the framework-dependent `.exe` directly asked to install the .NET Desktop Runtime. A self-contained local publish was built at `.tools/probe-publish/BandwidthProbe.App.exe`; it opens without that runtime prompt. It is ignored by Git and is not a signed release or installer. To recreate it:

```powershell
dotnet publish stage-a/BandwidthProbe.App/BandwidthProbe.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o .tools/probe-publish
```

The probe's working JSONL files go in the repository's ignored `results/` folder. **Pause & export JSONL** copies a completed session to a file you choose. The JSONL contains event metadata and byte counts, never packet contents, URLs, or remote addresses. A session-summary record at the end carries loss and data-gap counters.

## Known limits

- The current gate is NO-GO: one warmed idle CPU run exceeded the provisional target even though a later 30-minute collector run passed. UI memory, LAN, VPN, PID reuse, adapter-change, SRUM, and recovery checks are incomplete.
- A normal user cannot start collection on the tested machine. The app shows the denial and a data-gap state.
- Adapter counters come from Windows adapter statistics and are separate from ETW app totals. They are not expected to reconcile on loopback or VPN paths.
- Only controlled loopback transfer byte accuracy has been established. No claim is made about ISP billing, protocol headers, retransmissions, or VPN encapsulation.
