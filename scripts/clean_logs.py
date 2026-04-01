#!/usr/bin/env python3
"""
Log cleaner utility for Ethical Hacker Toolkit
Removes old log entries based on date or size
Author: Jet
GitHub: https://github.com/JettRnh
"""

import os
import sys
import time
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import LOG_DIR, LOG_FILE
from core.logger import log

def get_file_age_days(filepath):
    """Get file age in days"""
    if not filepath.exists():
        return 0
    modified = datetime.fromtimestamp(filepath.stat().st_mtime)
    age = datetime.now() - modified
    return age.days

def get_file_size_mb(filepath):
    """Get file size in MB"""
    if not filepath.exists():
        return 0
    return filepath.stat().st_size / (1024 * 1024)

def rotate_log(log_file, max_size_mb=10, keep_backups=3):
    """Rotate log file if it exceeds max size"""
    if not log_file.exists():
        return
    
    size_mb = get_file_size_mb(log_file)
    
    if size_mb > max_size_mb:
        log.info(f"Log file {log_file} exceeds {max_size_mb}MB, rotating...")
        
        # Rotate existing backups
        for i in range(keep_backups - 1, 0, -1):
            old = log_file.with_suffix(f".log.{i}")
            new = log_file.with_suffix(f".log.{i+1}")
            if old.exists():
                old.rename(new)
        
        # Move current log to backup
        backup = log_file.with_suffix(".log.1")
        log_file.rename(backup)
        
        log.success(f"Log rotated. Backup: {backup}")

def clean_old_logs(log_dir, days=30):
    """Delete logs older than specified days"""
    if not log_dir.exists():
        return 0
    
    deleted = 0
    cutoff = datetime.now() - timedelta(days=days)
    
    for log_file in log_dir.glob("*.log*"):
        if log_file.is_file():
            modified = datetime.fromtimestamp(log_file.stat().st_mtime)
            if modified < cutoff:
                log_file.unlink()
                deleted += 1
    
    return deleted

def main():
    """Main cleanup function"""
    print("\nEthical Hacker Toolkit - Log Cleaner")
    print("====================================")
    print()
    
    # Check current status
    if LOG_FILE.exists():
        size_mb = get_file_size_mb(LOG_FILE)
        age_days = get_file_age_days(LOG_FILE)
        print(f"Current log: {LOG_FILE}")
        print(f"  Size: {size_mb:.2f} MB")
        print(f"  Age: {age_days} days")
    else:
        print("No log file found.")
    
    # Check backup logs
    backups = list(LOG_DIR.glob("*.log.*"))
    if backups:
        print(f"\nBackup logs: {len(backups)} files")
        total_size = sum(get_file_size_mb(f) for f in backups)
        print(f"  Total size: {total_size:.2f} MB")
    
    print()
    print("Options:")
    print("  1. Rotate log (if > 10MB)")
    print("  2. Delete logs older than 30 days")
    print("  3. Delete all backup logs")
    print("  4. Delete everything (logs and backups)")
    print("  5. Exit")
    print()
    
    choice = input("Select option [1-5]: ").strip()
    
    if choice == "1":
        rotate_log(LOG_FILE, max_size_mb=10, keep_backups=3)
        print("Log rotation completed.")
    
    elif choice == "2":
        deleted = clean_old_logs(LOG_DIR, days=30)
        print(f"Deleted {deleted} old log files.")
    
    elif choice == "3":
        backups = list(LOG_DIR.glob("*.log.*"))
        for backup in backups:
            backup.unlink()
        print(f"Deleted {len(backups)} backup logs.")
    
    elif choice == "4":
        if LOG_FILE.exists():
            LOG_FILE.unlink()
        backups = list(LOG_DIR.glob("*.log.*"))
        for backup in backups:
            backup.unlink()
        print("All logs deleted.")
    
    elif choice == "5":
        print("Exiting.")
    
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
