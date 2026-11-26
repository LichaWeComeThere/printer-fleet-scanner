# Operator notes

Short version for whoever keeps the scanner running on a laptop. The full option list is in the [README](../README.md).

## Start it

```powershell
cd "C:\path\to\printer-fleet-scanner"
powershell -ExecutionPolicy Bypass -File .\Scan-PrinterFleet.ps1
```

## Stop it

Press **Q** in the window. Ctrl+C also works; at most about 3 minutes of work is lost. Start it again with the same two lines and it continues where it stopped.

## What's in the folder

| File | What it is |
| --- | --- |
| `Scan-PrinterFleet.ps1` | the app |
| `fleet_printers.csv` | the master list, one row per printer. Open a **copy** in Excel; Excel locks the file |
| `fleet_log.txt` | every event: `NEW`, `MOVED`, `GONE`, `BACK`, `CHECK`, `PASS`, `NETWORK` |
| `fleet_state.txt` | where it is in the current pass |
| `fleet_seed.csv` | optional starting list, only used if `fleet_printers.csv` is missing |

## Status column

| Status | Meaning |
| --- | --- |
| `ACTIVE` | answered the last check |
| `MISSED 1 CHECK` | did not answer once (could be a lost packet) |
| `NOT ANSWERING since …` | did not answer two checks in a row |

## How it runs

- One pass = every address in the ranges you gave it. All of `10.0.0.0/8` takes about 7–8 hours at the default 800 packets/s.
- Every 60 minutes it re-checks every known printer at its last address.
- If **no** printer answers (the laptop lost the network) it logs `NETWORK`, pauses, and retries every 5 minutes instead of marking everything `GONE`.

## Common options (add to the start line)

| Option | Effect |
| --- | --- |
| `-PacketsPerSecond 1500` | faster passes (~4 h); `400` = gentler (~15 h) |
| `-RecheckMinutes 30` | re-check known printers more often |
| `-Ranges 10.1.0.0/16,10.2.0.0/16` | sweep only these ranges |
| `-Hours 24` / `-Passes 3` | stop by itself |
| `-Community <name>` | SNMP read community if it isn't `public` |

## Keep it running

- Laptop on power, on **Ethernet** (Wi-Fi drops have stopped it before), lid **open**, PowerShell window open (minimized is fine).
- Only run one copy at a time.
- Tell the network team it's running; it looks like a scan because it is one.
