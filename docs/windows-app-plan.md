# Windows bandwidth desktop app — revised plan

Status: Stage A probe built and partially validated; current decision **NO-GO** (see `PHASE_A_REPORT.md`). Stage B is planning only until Stage A receives GO or GO WITH CHANGES **and the user approves**. Last reviewed: 2026-10-18.

## Changes made

1. **Desktop app first.** Replaced the CLI-first milestone with a measurement library and a deliberately plain desktop probe UI. The earlier CLI idea was only a way to reduce measurement risk.
2. **ETW source.** Moved the first experiment to the registered `Microsoft-Windows-Kernel-Network` provider in our own named session using TraceEvent. The provider is installed on this Windows 11 machine (`logman query providers` confirmed its GUID and IPv4/IPv6 keywords). The older NT Kernel Logger documentation describes a different, shared session and is retained only as a fallback experiment. No other tool's session will be stopped or changed. [Microsoft provider example](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace-etw), [Microsoft TraceEvent guide](https://github.com/microsoft/perfview/blob/main/documentation/TraceEvent/TraceEventProgrammersGuide.md), [system trace session rules](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session).
3. **SRUM.** Added a read-only study of Windows' saved usage data, including access rights, fields, time buckets, and a comparison to a known transfer. This machine denied the normal user direct access to `SRUDB.dat`; its usefulness and pre-install coverage remain unverified. We will not promise pre-install history until the study passes. Microsoft's `GetAttributedNetworkUsageAsync` exposes delayed per-attribution usage, but requires the restricted `networkDataPlanProvisioning` capability, which Microsoft describes for mobile-operator apps; it is not an assumed general desktop-app route. [Attribution API](https://learn.microsoft.com/en-us/uwp/api/windows.networking.connectivity.connectionprofile.getattributednetworkusageasync), [capability declaration](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations).
4. **VPN.** Added a test for app traffic plus VPN process traffic and adapter totals. Mark unverified when no usable VPN is available.
5. **Byte meaning and tolerance.** Replaced the unproven claim that events count payload only with an experiment. Before testing, the pass bar is within **10%** of known transfers of **at least 100 MB**, for each test process and the aggregate. Report the measured ratio, retransmissions, protocol overhead, and any reason the figures differ. The ETW event includes a `size` field, but its exact accounting relationship to file bytes and adapter bytes still needs measurement. [Microsoft network event example](https://learn.microsoft.com/en-us/windows/uwp/debug-test-perf/device-portal-api-core), [legacy event field reference](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-sendipv4).
6. **Attribution.** Added explicit display rules for services hosted by `svchost.exe`, packaged apps, protected processes, and unresolved names. The report will quantify Unknown/System bytes.
7. **Privilege boundary.** Added a decision test for an elevated collector service. The provisional production design is an elevated service that owns the local database under ProgramData, with an unelevated UI communicating through a named pipe restricted to allowed local users. Multi-user isolation is specified below. A service is not yet declared necessary. Windows restricts who can control tracing sessions. [ETW permissions](https://learn.microsoft.com/en-us/windows/win32/etw/controlling-event-tracing-sessions).
8. **Packaging.** Removed the Store default. Test MSIX plus service installation and Store acceptance; retain a signed traditional installer as fallback. MSIX can package Windows services on current Windows, but service packages require administrative installation, and Store acceptance is a separate unknown. [MSIX service deployment](https://learn.microsoft.com/en-us/windows/msix/desktop/managing-your-msix-deployment-targetdevices), [distribution paths](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/choose-distribution-path).
9. **Windows UI choice.** Chose WPF for Stage A and provisional Windows release: it is Windows-native, works with a plain local build, and does not add WinUI's runtime/deployment layer. Avalonia is no longer driving the design; revisit only if a later platform project earns it. [WPF scope](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/overview/), [unpackaged WinUI deployment](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/unpackage-winui-app).
10. **Competition and numeric gates.** Added a verified positioning paragraph and provisional CPU, memory, and event-loss limits below.

## Product in one paragraph

This is a real Windows desktop app for answering "which app used my bandwidth, and when?" The user sees current upload and download, a ranked app list, and history. Values are **measured network bytes, not ISP billing**; local traffic, VPNs, protocol overhead, and missed events can make figures differ. No packet contents, URLs, or blocking are collected or offered.

## Positioning

We must not claim that basic per-app graphs are new. GlassWire already offers graphs and per-app usage, NetLimiter offers monitoring plus limits and firewall rules, NetBalancer offers monitoring and prioritization, and NirSoft's NetworkUsageView reads Windows' saved usage records. Our proposed focus is a small, transparent, local-first bandwidth explanation tool with visible measurement gaps, a documented Unknown/System bucket, and clear export. Whether that is compelling enough is a product question to test with users. [GlassWire](https://www.glasswire.com/features/), [NetLimiter](https://netlimiter.com/features), [NetBalancer](https://netbalancer.com/features), [NirSoft NetworkUsageView](https://www.nirsoft.net/utils/network_usage_view.html).

## Scope and measures

- Stage A targets Windows 11 x64 on this machine. Other Windows builds need separate tests.
- Current rate means bytes per second, not a speed test. Show download and upload separately.
- Session totals begin when collection starts. Before-install and off-time history remain unavailable unless the SRUM study proves a limited historical view; any imported SRUM data will be labeled by source and time resolution.
- Adapter totals and app totals are separate measurements. Do not force them to sum to the same number. Identify adapters as Wi-Fi, Ethernet, VPN/virtual, loopback, or unknown when Windows supplies enough information.
- The first test format is JSON Lines (JSONL), one versioned record per line. Store UTC time, sample interval, direction, byte count, process ID, process start time if known, app/service/package label and attribution state, adapter ID/type if known, dropped-event count, and data-gap status. Do not include payload, URLs, or remote addresses in exports.
- The existing Apache/Nginx log analyzer remains separate from this desktop monitor.

## Stage A — measurement core and plain probe UI

**Code shape:** `IBandwidthCollector` has start, pause/stop, plain snapshots, and JSONL export. ETW-specific classes stay behind it. The plain WPF UI runs the collector in-process now; a service can host the same collector later. The UI never receives ETW event objects.

**Probe screen:** live per-process table with separate download/upload columns; adapter totals with type labels; dropped-event counter; visible gap/error banner; Start and Pause; Export session to JSONL. No final design, installer, or persistent database. Temporary exports go under `results/` and are ignored by Git. No background capture after the probe closes.

**ETW experiment:** enable `Microsoft-Windows-Kernel-Network` in a uniquely named private session using TraceEvent. Restrict to required network keywords/events. Use the network event's payload PID and size, not the generic ETW header PID. Decode TCP/UDP, IPv4/IPv6 send/receive; count only byte-bearing data events. Own only our named session and stop only that session on clean exit. On a crash, detect a stale session and report it; do not remove an unknown owner. Record event count, events lost, buffer loss, and parse failures. If this provider does not produce usable events, try the older system-provider method only in an isolated test and report why.

**Attribution display:**

- Normal process: friendly app name plus executable name; identity is PID + process start time, so PID reuse does not merge apps.
- Packaged app: package/display name when Windows resolves it; otherwise executable plus PID.
- `svchost.exe`: show a service name only when mapping to a single service is reliable. Otherwise show `Windows services (svchost.exe)` plus PID, without inventing a specific service.
- Protected or exited process: retain the last known name; otherwise `Unknown process (PID …)`.
- PID 0/4 or clearly system-owned activity: `System`. Missing/unreliable attribution: `Unknown`. Report both buckets in bytes and percent of observed app-event bytes.

**Privilege decision:** test collection under (a) an ordinary user, (b) a user in Performance Log Users, and (c) an elevated session. A group-membership change cannot be tested without an authorized local account change. Decide `service required: yes/no/conditional` from these runs. Provisional release layout, if required: a narrow elevated service owns collection and SQLite under ProgramData; the unelevated UI uses a versioned named-pipe protocol with an ACL for authorized local users. Never use a world-writable pipe. Service reads the connecting user's Windows identity and returns only that user's process history by default; machine-wide data requires a deliberate administrator view. Test concurrent Windows users, fast user switching, and service/UI version mismatch before release. Stage A may use an in-process collector and has no SQLite or service implementation.

### Predeclared pass limits

- Known transfers: each process and aggregate within ±10% for each controlled transfer of at least 100 MB. Report measured/expected ratio. A file transfer can include networking overhead, so comparisons must state the reference: application file bytes and adapter bytes.
- Event loss: zero lost events in each 100 MB controlled run; under 0.1% during a 10-minute high-rate stress run, with any loss visibly marking affected samples as partial.
- Overhead: collector average CPU ≤2% of one logical CPU while idle and ≤5% during a sustained 100 Mbps test; collector private memory ≤150 MB after 30 minutes; UI private memory ≤250 MB after 30 minutes. These are provisional gates, not measured claims. Record machine, traffic rate, events/second, and baseline without the probe. Revisit thresholds only with documented evidence.
- Recovery: denial, collector kill, or session conflict produces a visible gap/error within 3 seconds, never an apparently complete zero.

### Validation matrix

Run and mark each row PASS, FAIL, BLOCKED, or UNVERIFIED: single process download/upload; two concurrent processes; TCP/UDP; IPv4/IPv6; loopback/LAN; short-lived process; PID reuse; Wi-Fi/Ethernet or adapter change; VPN double-counting; permission denial; same-name session conflict; collector kill/restart; idle and loaded CPU/memory/events-per-second; SRUM access, columns, time buckets, and known-transfer comparison. Do not manipulate another tool's ETW session. Raw Stage A JSONL and test notes live in `results/`.

### Required report and gate

`PHASE_A_REPORT.md` must contain a permission matrix, expected-versus-measured table with ratio and pass/fail, loss/overhead numbers, Unknown/System percentage, SRUM and VPN findings, unverified items, and an explicit `GO`, `GO WITH CHANGES`, or `NO-GO` decision. It must explicitly answer: **Does the product need a privileged service?** No Stage B implementation starts without a GO/GO WITH CHANGES result **and user approval**.

## Stage B — real UX, plan only

This is a written screen spec, not an implemented design:

| Screen | What the user sees | Main actions |
| --- | --- | --- |
| **Live** | Current total download and upload rates, a small rate-over-time graph, the top five apps, a permanent **Unknown or system traffic** row, and adapter names/types. One sentence says: “Usage is measured network bytes and may differ from your internet provider's bill.” | Start/Pause, open an app, export the current session. |
| **Apps** | All apps ranked by session download, upload, or combined usage. Each row keeps the app name, executable or package name if known, and an exact-byte detail view. Shared `svchost.exe` traffic is labelled “Windows services” unless one service is reliably known. | Sort, search locally by name, open app detail. |
| **Timeline** | Session, today, and recent-days tabs. A chart and a table show separate download/upload totals for each time bucket. Show exactly when the app was collecting; never draw a continuous line through a gap. Data collected before installation appears only if the SRUM study later proves a clearly labelled historical source. | Change time range, select an app, export selected data. |

**State rules:** Before the first capture, explain Start in one short sentence. When offline, show “No active connection” while keeping earlier history visible. When there are zero observed bytes, show “No traffic measured yet,” not an empty broken chart. When some events were lost or an adapter changed, mark the affected bucket **Partial** with the known bytes and a short explanation. If the collector stops or lacks permission, show a prominent **Data gap** with its start time and a retry action. A paused session shows its last totals and an obvious Paused label. Unknown/System is always visible, including when it is zero, so users can judge attribution quality.

**Numbers:** Use bytes for exact details/export and binary units (KiB, MiB, GiB) for readable totals and bytes/second for rates. Below 10 of a unit show one decimal; at 10 or more show at most one decimal. A small nonzero amount must show a less-than value (for example `<0.1 KiB`) instead of `0`. Use the same rules in every screen and state whether a number is session, today, or recent-days usage. Keep adapter and app totals separate because they measure different paths.

**Access:** Every action must work with keyboard only; focus must remain visible. Give charts a text summary and app rows clear screen-reader names. Test Windows high contrast and text scaling; never rely on color alone to distinguish upload, download, or gaps. Do not build Stage B before the gate.

## Packaging and updates — later release work

Build and use a local probe without packaging during Stage A. For public release, compare a service-bearing MSIX with Store submission against a signed installer from our own website. Store acceptance is unverified, and Store is not assumed to be the default. A direct download has no Windows usage fee, but trusted signing/hosting may cost money; unsigned apps can trigger SmartScreen warnings. [Code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options), [SmartScreen](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).

Keep data outside the installed app directory. Version the UI/service protocol and saved schema. A new version must read old data or migrate a copy, preserve a rollback copy, and leave the current install working if download, verification, installation, or migration fails. Test clean install, update, interrupted update, rollback, and uninstall with retained history before release. Signed MSIX with `.appinstaller` can update outside the Store; a signed traditional installer needs its own tested updater. [App Installer updates](https://learn.microsoft.com/en-us/windows/msix/app-installer/auto-update-and-repair--overview).

## Current measurement result and remaining uncertainty

The private provider produced per-process events and all controlled 100 MiB loopback transfers matched application bytes in both directions. An 11-minute, 7.5 GB-per-direction stress run also matched bytes and reported zero ETW loss. Ordinary-user collection was denied while elevation worked. A 30-minute idle run passed collector memory and CPU limits, with zero reported loss, including two-minute windows near 109–111 events/s. An earlier warmed 30-second run at 104.6 events/s exceeded the CPU limit, so that discrepancy needs investigation. SRUM content/history, VPN behavior, physical LAN traffic, PID reuse, UI memory, Performance Log Users, and Store acceptance remain unverified or blocked. The complete evidence and decision are in `PHASE_A_REPORT.md`; an untestable item cannot silently be counted as passing.
