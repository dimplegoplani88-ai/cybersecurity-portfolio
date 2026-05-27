# ⌨️ Project 8 — Educational Keylogger

A Python keylogger that captures keyboard events with timestamps and logs them locally. Built to demonstrate how keyloggers work at a technical level — for defensive security awareness.

## ⚠️ Legal & Ethical Notice

> **Use ONLY on systems you own or have explicit written permission to monitor.**
> Unauthorized keylogging is illegal in most countries and a serious criminal offence.
> This tool exists purely for educational and authorized testing purposes.

## Features

- Captures keystrokes with timestamps
- Logs to a local file with session start/end markers
- Auto-saves buffer every N seconds (configurable)
- Silent mode (no terminal output)
- Press ESC to stop cleanly
- Handles special keys (Enter, Backspace, Tab, arrow keys, F1–F12)

## Requirements

```bash
pip install pynput
```

## Usage

```bash
# Basic (logs to keylog.txt)
python keylogger.py

# Custom log file
python keylogger.py -o my_session.txt

# Silent mode (only writes to file)
python keylogger.py --silent

# Custom flush interval (every 10 seconds)
python keylogger.py --flush 10
```

Press **ESC** to stop at any time.

## Skills Demonstrated

- `pynput` keyboard listener API
- Threading and timer management
- File I/O with buffered writes
- Signal handling (Ctrl+C graceful exit)
- Understanding of keylogger internals (for blue-team/defensive awareness)
