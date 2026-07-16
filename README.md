# 401/403 Overrule

A Burp Suite extension for hunting access-control bypasses on `401`/`403` protected endpoints. Right-click any request, send it to **401/403 Overrule**, and it fires a curated set of well-known WAF/auth bypass techniques at the target — then scores every response against an auto-calibrated baseline so real bypasses stand out from noise.

## Features

- **25 technique categories**, each in its own tab, covering:
  - Verb tampering & verb case switching
  - Header spoofing (IP / URL / generic), simple header pairs, hop-by-hop headers, header confusion
  - `Forwarded` trust, proto confusion, IP encoding tricks
  - End-path / mid-path payloads, path normalization, suffix tricks
  - Double encoding, Unicode encoding
  - Method override (header & query param)
  - Host override, path case switching, User-Agent sweeps
  - HTTP version / parser quirks, absolute-URI requests
  - Raw-socket techniques: duplicate headers, authority confusion, TE/CL desync
- **Auto-calibrated baseline** — sends extra probes to work out a safe length tolerance before judging results, so noisy targets (dynamic tokens, timestamps) don't flood you with false positives.
- **Strict calibration mode** — optionally require the full scoring engine (status + length + body hash + headers) to agree, instead of falling back to a simple status/length diff.
- **"Only show interesting" filter** — hide payloads that didn't deviate from baseline, or show everything for manual review.
- **Per-tab controls** — Run, Stop, Resume, Send Selected/All to Repeater, Clear Selected/All.
- **Run All Tabs** — fire every technique category in one pass.
- **Results table** per tab: `Sel | URL | Variant | Status | Length`, with request/response viewers on row click and right-click send-to-Repeater/Intruder/Comparer.

## Requirements

- [Burp Suite](https://portswigger.net/burp) (Community or Pro)
- [Jython standalone JAR](https://www.jython.org/download) (2.7.x) configured under **Extender → Options → Python Environment**

## Installation

1. Download `burp_403_overrule.py` from this repo.
2. In Burp, go to **Extender → Options** and make sure the Jython standalone JAR is set as your Python environment.
3. Go to **Extender → Extensions → Add**, set extension type to **Python**, and select `burp_403_overrule.py`.
4. A new **401/403 Overrule** tab will appear in Burp's top-level tab bar.

## Usage

1. Find a request that returns `401`/`403` in Proxy, Repeater, or Target.
2. Right-click it → **Send to 403 Bypass**.
3. Switch to the **401/403 Overrule** tab. The target request is now loaded.
4. Adjust settings if needed:
   - `Auto-calibrate baseline` — leave on for noisy/dynamic targets.
   - `Strict calibrate` — turn on if you're seeing too many false positives.
   - `Only show interesting` — turn off to log every payload sent.
5. Click **Run All Tabs**, or open an individual technique tab and click **Run**.
6. Review results — rows that differ meaningfully from the baseline are flagged as interesting. Click a row to view the full request/response, or right-click to send it to Repeater/Intruder/Comparer for further testing.

## Disclaimer

This tool is intended for authorized security testing only. Only run it against targets you own or have explicit permission to test.

## License

MIT
