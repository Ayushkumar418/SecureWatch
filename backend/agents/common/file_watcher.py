"""
file_watcher.py — Cross-platform file tailing utility.

Provides efficient file monitoring that:
  - Detects new lines appended to a file (tail -f style)
  - Handles log rotation (file truncated or renamed)
  - Gracefully handles missing files
  - Works on both Linux and Windows
"""
import os
import time
import logging
from pathlib import Path

log = logging.getLogger("file_watcher")


class FileTailer:
    """
    Tail a file and yield new lines as they are appended.

    Usage:
        tailer = FileTailer("/var/log/auth.log")
        for line in tailer.follow():
            process(line)
    """

    def __init__(self, filepath, sleep_interval=0.5, from_end=True):
        """
        Args:
            filepath: Path to the file to tail.
            sleep_interval: Seconds between polls when no new data.
            from_end: If True, start from end of file (skip existing content).
                      If False, read from beginning.
        """
        self.filepath = Path(filepath)
        self.sleep_interval = sleep_interval
        self.from_end = from_end
        self._inode = None

    def follow(self):
        """
        Generator that yields new lines as they are appended to the file.
        Handles log rotation by detecting inode/size changes.
        """
        while True:
            if not self.filepath.exists():
                log.debug("Waiting for %s to appear...", self.filepath)
                time.sleep(self.sleep_interval * 4)
                continue

            try:
                with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                    # Track file identity for rotation detection
                    try:
                        stat = os.fstat(f.fileno())
                        self._inode = getattr(stat, "st_ino", None)
                    except (OSError, AttributeError):
                        self._inode = None

                    if self.from_end:
                        f.seek(0, 2)  # jump to end
                        self.from_end = False  # only skip on first open
                    else:
                        f.seek(0, 2)  # also start from end on reopen after rotation

                    log.info("Tailing %s (pos=%d)", self.filepath, f.tell())

                    while True:
                        line = f.readline()
                        if line:
                            stripped = line.rstrip("\n\r")
                            if stripped:
                                yield stripped
                        else:
                            # No new data — check for rotation
                            if self._check_rotation(f):
                                log.info("Log rotation detected for %s", self.filepath)
                                break  # reopen the file
                            time.sleep(self.sleep_interval)

            except FileNotFoundError:
                log.warning("File disappeared: %s — waiting for it to reappear", self.filepath)
                time.sleep(self.sleep_interval * 4)
            except PermissionError:
                log.error("Permission denied: %s — run with appropriate privileges", self.filepath)
                time.sleep(self.sleep_interval * 10)
            except Exception as e:
                log.error("Error reading %s: %s", self.filepath, e)
                time.sleep(self.sleep_interval * 4)

    def _check_rotation(self, open_file):
        """
        Detect if the file has been rotated (renamed/truncated).
        Returns True if the file should be reopened.
        """
        try:
            if not self.filepath.exists():
                return True

            current_stat = os.stat(self.filepath)
            open_stat = os.fstat(open_file.fileno())

            # Check inode change (Linux log rotation: rename + create new)
            current_inode = getattr(current_stat, "st_ino", None)
            open_inode = getattr(open_stat, "st_ino", None)
            if current_inode and open_inode and current_inode != open_inode:
                return True

            # Check size shrink (file was truncated)
            current_pos = open_file.tell()
            if current_stat.st_size < current_pos:
                return True

            return False

        except (OSError, ValueError):
            return True
