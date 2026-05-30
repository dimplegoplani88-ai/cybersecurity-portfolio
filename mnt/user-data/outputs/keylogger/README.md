# Educational Keylogger

A Python keylogger that captures keyboard events with timestamps and logs them to a file. Built to understand how keyloggers work from a defensive security perspective.

> ⚠️ **LEGAL WARNING**: Use this tool **only on systems you own** or have **explicit written permission** to monitor. Unauthorized keylogging is a criminal offense in most jurisdictions. This project exists solely for education and security research.

## What This Teaches

Keyloggers are one of the most common malware components. Understanding how they work helps you:
- Recognize keylogger behavior in malware analysis
- Understand why endpoint detection tools flag keyboard hook APIs
- Learn about OS-level input event systems
- Appreciate why password managers with auto-fill (not typing) matter

## Features

- Captures all keystrokes with timestamps
- Readable labels for special keys (`[ENTER]`, `[BACKSPACE]`, `[CTRL]`, etc.)
- Auto-saves to file on a configurable interval (prevents data loss on crash)
- Session headers and footers with duration and key count
- Silent mode (log only, no terminal output)
- Press `ESC` to stop cleanly
- Ctrl+C also stops gracefully

## Requirements

- Python 3.6+
- Works on Windows, macOS, and Linux

```bash
pip install -r requirements.txt
```

## Usage

### Basic (logs to `keylog.txt`, prints to terminal)

```bash
python keylogger.py
```

### Silent mode (log file only)

```bash
python keylogger.py --silent
```

### Custom log file

```bash
python keylogger.py -o session_log.txt
```

### Custom auto-save interval (every 10 seconds)

```bash
python keylogger.py --flush 10
```

Press **ESC** to stop at any time.

## Sample Output (`keylog.txt`)

```
============================================================
SESSION START: 2025-09-14 21:03:11
============================================================
Hello[SPACE]World[ENTER]
password123[BACKSPACE][BACKSPACE][BACKSPACE]
[CTRL]c
============================================================
SESSION END: 2025-09-14 21:04:02
Duration: 0:00:51 | Keys captured: 37
============================================================
```

## How It Works

This tool uses `pynput`, a cross-platform library that hooks into the OS keyboard input API:

- **Windows**: Uses the Win32 `SetWindowsHookEx` API
- **macOS**: Uses the Quartz event tap API (may require Accessibility permissions)
- **Linux**: Uses X11 event capture or `evdev`

This is the same mechanism used by malicious keyloggers — which is why antivirus software flags it. Running this will likely trigger your AV. That's expected and educational.

## macOS Note

macOS requires granting Accessibility permissions to the terminal running this script:
**System Settings → Privacy & Security → Accessibility → enable your Terminal app**

## What You'll Learn

- How OS keyboard hooks work at a system level
- Threading for periodic I/O flushes without blocking input capture
- Signal handling (`SIGINT`) for graceful shutdown
- Why keyloggers are effective and how defenders detect them (behavioral heuristics, not signatures)

## Disclaimer

For educational and authorized security research use only. The author is not responsible for misuse. Unauthorized use is illegal.
