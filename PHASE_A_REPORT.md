# Stage A measurement report

**Decision: NO-GO for Stage B (2026-10-18).** The controlled loopback transfers passed the predeclared ±10% byte test, and the long stress run reported zero loss. A new 30-minute collector run passed the private-memory limit and had low CPU, including at background event rates near an earlier CPU failure. The discrepancy remains unexplained, and several required cases have not been validated. Stage B remains a written plan only and needs a new GO or GO WITH CHANGES report plus user approval before implementation.

## What was built and run

- A UI-free `IBandwidthCollector` implementation uses `Microsoft-Windows-Kernel-Network` and process events through TraceEvent in a uniquely named private ETW session. It does not use the shared NT Kernel Logger or alter another tool's session.
- A plain WPF desktop probe shows separate per-process download/upload, current rates, adapter totals and type labels, lost/parse/export counters, a data-gap banner, Start/Pause, and JSONL export. There is no installer, database, or Stage B UX.
- The solution built with .NET SDK 10.0.402: **0 warnings, 0 errors**. The WPF process stayed open for a three-second, normal-user runtime smoke check. A later visual check of a self-contained publish found that the pre-Start window incorrectly showed a data-gap banner and changing adapter counters. The code was changed so the initial values stay zero and paused counters freeze; it built successfully, but a second visual check was stopped by the user, so the UI fix is **not visually verified**.
- On 2026-10-18, a second Release build completed with **0 warnings, 0 errors**. A new ordinary-user start check was denied as expected and reported `dataGap: true` with `sessionFileAvailable: false` (`results/permission-smoke-20261018-103826.json`). The collector now clears the exportable session reference after a failed ETW start. This checks the collector state, **not** the WPF button or banner visually.
- The WPF Start handler no longer waits behind a modal error dialog before showing a failed-start gap. It keeps the error banner visible across timer refreshes until the next Start attempt. This was build checked only; the visual timing gate remains unverified.
- The JSONL event files and machine-readable test reports are under `results/` (ignored by Git). The comparison below uses the controlled transfer's application byte count as the reference. Loopback can be counted once for sending and once for receiving; those are separate process directions, not an ISP total.

## Permissions matrix

| Context | Actually tested | Result |
| --- | --- | --- |
| Ordinary user, medium integrity, local Administrators membership disabled by UAC | Yes | **FAIL to start ETW**: Access Denied, “Administrator rights required to start ETW”. See `results/permission-smoke-20261018-095236.json`. |
| Performance Log Users member | No | **UNVERIFIED.** Current user is not a member. Testing requires a separate authorized account/group change and a fresh sign-in. |
| Elevated current user | Yes, with user-approved UAC | **PASS to start**: 1,696 events in five seconds, zero reported ETW loss, zero parse failures, zero export drops. See `results/permission-smoke-20261018-095319.json`. |

**Does the product need a privileged service?** For a normal user on this default setup, **yes, an elevated collection component is needed** to provide automatic per-app monitoring. A Windows service is the provisional release design because it can collect while the unelevated UI runs. The Performance Log Users result and multi-user security tests are still needed before declaring that design final. The Stage A app runs in-process only; it does not install a service.

A fresh `whoami /groups` check on 2026-10-18 again showed the current medium-integrity token with Administrators as deny-only and no Performance Log Users membership. The available adapters were active Wi-Fi and WSL virtual Ethernet, with physical Ethernet disconnected. These observations do not substitute for a Performance Log Users test or a real LAN transfer.

## Expected versus measured

The predeclared pass rule was 0.90–1.10 measured/expected for each process and the controlled aggregate on transfers of at least 100 MB. The expected value in a row is application bytes for that direction. `1.000` means an exact match to that reference in these tests; it does **not** prove how headers, retransmissions, VPN encapsulation, or physical adapter bytes are counted on other paths.

| Controlled run | Expected | Measured sender upload | Measured receiver download | Ratio, each direction | ETW loss / parse / export drops | Result |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| TCP IPv4 loopback, short-lived child | 104,857,600 B | 104,857,600 B | 104,857,600 B | 1.000 / 1.000 | 0 / 0 / 0 | **PASS** |
| TCP IPv6 loopback | 104,857,600 B | 104,857,600 B | 104,857,600 B | 1.000 / 1.000 | 0 / 0 / 0 | **PASS** |
| UDP IPv4 loopback | 104,857,600 B | 104,857,600 B | 104,857,600 B | 1.000 / 1.000 | 0 / 0 / 0 | **PASS** |
| Two concurrent TCP IPv4 receivers | 209,715,200 B total | 209,715,200 B | 104,857,600 B each; 209,715,200 B total | 1.000 aggregate and each process | 0 / 0 / 0 | **PASS** |
| Sustained roughly 100 Mbps TCP loopback, 30 s | 375,000,000 B | 375,000,000 B | 375,000,000 B | 1.000 / 1.000 | 0 / 0 / 0 | **PASS** for bytes |
| Long TCP loopback stress, 11.05 min, actual 90.5 Mbps | 7,500,000,000 B | 7,500,000,000 B | 7,500,000,000 B | 1.000 / 1.000 | 0 / 0 / 0 | **PASS** for bytes and reported loss |

Reports: `results/loopback-transfer-20261018-095712.json`, `results/ipv6-loopback-transfer-20261018-095809.json`, `results/udp-loopback-transfer-20261018-100214.json`, `results/concurrent-loopback-transfer-20261018-100336.json`, `results/overhead-100mbps-20261018-100733.json`, and `results/stress-100mbps-10min-20261018-102415.json`. The stress test's name records its 100 Mbps pacing target; the measured elapsed time gives 90.5 Mbps average. Its JSONL session-summary has two more events than the report snapshot because the collector continued briefly between the snapshot and pause. The first UDP attempt was a faulty, over-slow test generator and failed before a valid measurement; `results/udp-loopback-transfer-20261018-100138.json` is retained as an invalid attempt, not a collector failure.

The exact 1.000 ratios indicate that, on these local transfers, the provider's `size` field agreed with bytes written/read by the test application. There was no induced retransmission or physical-path comparison, so “payload bytes rather than headers/retransmissions” remains a hypothesis outside these runs. Aggregate controlled upload and download also matched exactly when compared by direction; adding both directions counts loopback traffic twice by design.

## Attribution and Unknown/System

The short-lived test client was initially shown as Unknown because it exited before a name lookup. Adding the process provider resolved the client's name as `dotnet` in the retest. The collector keys visible rows by PID and known start time, and labels `svchost.exe` as “Windows services (svchost.exe)” without claiming a particular service. Package display names and reliable service mapping are not implemented yet.

In the four 100 MiB controlled runs above, Unknown/System/service-labelled bytes were **0 B** of observed app-event bytes. In the 375 MB overhead run, they were **486 B of 756,524,949 B**, or **0.000064%**. In the long stress run, they were **18,400,571 B of 15,206,840,509 B**, or **0.121%**, including background traffic. This is a property of these sessions, not an expected future rate. The report's category combines unresolved process, System, and generic service rows; those must be split in a release report.

## Loss and overhead gates

| Gate | Observed | Result |
| --- | --- | --- |
| Zero ETW lost events in each controlled ≥100 MB run | Zero reported for the four 100 MiB tests and 375 MB run | **PASS** for those runs |
| <0.1% loss in ten-minute high-rate stress | 142,298 events in 11.05 min, zero reported loss, zero parse failures, zero export drops; 214.7 network events/s average | **PASS** for this run |
| Idle collector CPU ≤2% of one logical CPU | 4.75% over 30.24 s including startup; 3.84% over a separate warmed 30.11 s at 104.6 events/s; 0.59% over a warmed 120.06 s at 10.6 events/s. New 30-minute run averaged 0.21% at 40.0 events/s; its two-minute windows at 109.1 and 111.2 events/s used 0.25% and 0.39%. | **MIXED**: the long run passed, including comparable event-rate windows, but the earlier high-background failure is unexplained. |
| Loaded collector CPU ≤5% at 100 Mbps target | 4.02% over 36.50 s in short run; 0.57% over 11.05 min at actual 90.5 Mbps; traffic in child processes | **PASS** for these runs |
| Collector private memory ≤150 MB after 30 min | New 30-minute run: 19.2 MiB at the final sample and at the end; highest of fifteen two-minute samples was 19.5 MiB. Earlier short/loaded observations ranged from 15.3 to 20.7 MiB. | **PASS** for the UI-free validation process after 30 minutes. |
| UI private memory ≤250 MB after 30 min | UI launched for 3 s; memory not recorded | **UNVERIFIED** |
| Visible gap within 3 s after denial, collector kill, or session conflict | Denial sets gap/status in code; UI behavior under kill/conflict was not timed | **UNVERIFIED** |

Idle result files: `results/idle-30s-20261018-100655.json`, `results/warm-idle-30s-20261018-100909.json`, `results/warm-idle-120s-20261018-102717.json`, and `results/extended-idle-30min-20261018-111030.json`. CPU is this test process's consumed CPU time divided by wall time, as percent of one logical CPU. The new run warmed for ten seconds, then recorded fifteen two-minute windows over 30 minutes. It saw 73,324 events at the pre-pause snapshot, zero loss/parse/export drops and no data gap; the final JSONL summary contains 73,407 events, zero loss/parse/export drops and no data gap. The two counts differ because capture continued between snapshot and pause. The high-event windows show that event rate alone does not explain the earlier 3.84% result; process activity or measurement conditions may have differed. The 100 Mbps target run includes collection and result writing in the parent; traffic generation ran in child processes. A baseline without collection was not measured. Hardware: Windows 11 Home Single Language x64, build 26200, with Wi-Fi active and a WSL virtual adapter present.

After the new run exited, a read-only `logman query -ets` showed no remaining `BandwidthProbe.StageA` session. This confirms clean closure for that run; it does not test forced collector termination or same-name conflict recovery.

## SRUM and VPN

**SRUM — partial investigation, no accuracy claim.** The normal user was denied direct access to `C:\Windows\System32\sru\SRUDB.dat`. With approved elevation, read-only metadata succeeded: the file existed, was 74,121,216 bytes, and had a 2026-10-18 09:56:30 UTC last-write time (`results/srum-metadata.json`). Tables/fields, privilege needed for a supported extraction, time bucket size, pre-install coverage, and agreement with the known transfer were **not verified**. Microsoft documents a separate delayed per-attribution usage API, but it requires the restricted `networkDataPlanProvisioning` capability described for mobile-operator apps; it is not evidence of usable SRUM access for this app. [API](https://learn.microsoft.com/en-us/uwp/api/windows.networking.connectivity.connectionprofile.getattributednetworkusageasync), [capability](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations). The “no reconstruction before install” rule therefore stays in force for product claims; a later SRUM import may offer explicitly labelled historical estimates only after a successful comparison.

**VPN — BLOCKED.** No VPN adapter was active, and the user confirmed no VPN is available on this PC. Whether a VPN causes app plaintext and encrypted physical-adapter traffic to double count remains unverified. The UI must not claim a reconciled per-app/adapter total until that is tested.

## Full Stage A matrix

| Case | Status | Evidence or gap |
| --- | --- | --- |
| Single process upload/download, TCP IPv4 | **PASS** | 100 MiB loopback, ratio 1.000 per direction. |
| Concurrent processes | **PASS** | Two 100 MiB clients each attributed separately. |
| TCP and UDP | **PASS** | Controlled 100 MiB TCP and UDP runs. |
| IPv4 and IPv6 | **PASS** | Controlled TCP on both loopback families; IPv6 UDP not run. |
| Loopback and LAN | **PARTIAL** | Loopback passed; real LAN peer not available/tested. |
| Short-lived process | **PASS** in one scenario | Client exited before snapshot; process event supplied name. |
| PID reuse | **UNVERIFIED** | Key includes start time where known, but forced reuse was not run. |
| Adapter change | **UNVERIFIED** | No Wi-Fi/Ethernet change was induced. A new, missing, or reset adapter marks a gap in code; runtime behavior not validated. |
| VPN double counting | **BLOCKED** | User reports no VPN available. |
| Permission denial | **PASS** as negative test | Normal user denied; collector records a gap and error. |
| Same-name session conflict | **UNVERIFIED** | Unique session names avoid routine conflicts; conflict behavior was not forced. |
| Collector kill/restart | **UNVERIFIED** | Not timed or validated. |
| CPU/memory/event rate | **PARTIAL / MIXED** | Thirty-second high-background idle CPU failed; 30-minute idle CPU and collector memory passed, including 109–111 events/s windows; ten-minute stress loss passed. UI memory and the CPU discrepancy remain unresolved. |
| SRUM privileges, fields, granularity, accuracy | **PARTIAL** | File access tested; database content and comparison unverified. |

## Changes required before a new gate review

1. Investigate why the earlier warmed 30-second CPU run used 3.84% at 104.6 events/s while the new 30-minute run used 0.25–0.39% at 109–111 events/s. Record a comparable baseline and repeat if necessary before declaring the idle CPU gate reliable.
2. Run a 30-minute UI memory test. Validate visible gap behavior after a controlled stop of **our own** session and after a forced same-name conflict, without touching other tools' ETW sessions.
3. Validate PID reuse and adapter changes. Obtain a LAN peer for a physical-path comparison. VPN remains blocked until a VPN is available.
4. Finish a read-only SRUM schema/time-bucket and known-transfer study before considering any pre-install history claim.
5. Test a fresh Performance Log Users account and multi-user behavior before finalizing the elevated service, ProgramData database ownership, and ACL-protected named pipe.

The desktop app remains a Stage A probe. There is no production installer or updater yet. Stage B UX is specified in `docs/windows-app-plan.md` and has **not** been implemented.

Two of our own **different-name** private sessions overlapped successfully while the stress run was active: the second five-second session started, recorded 3,224 events, and reported zero loss and no gap (`results/permission-smoke-20261018-101433.json`). This confirms concurrent private sessions on this machine; it does not validate a same-name conflict.

The machine lacks a globally installed .NET Desktop Runtime, so launching the framework-dependent `.exe` directly showed a runtime-install prompt. A local **self-contained** Windows publish opened without that prompt (`dotnet publish ... --self-contained true -p:PublishSingleFile=true`). This is a packaging observation, not a finished installer. Computer Use was stopped with Escape during the follow-up UI check; no further desktop input was attempted.
