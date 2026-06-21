#!/usr/bin/env python3
"""
System Integrity Hash Checker - File Integrity Monitor (Simulator)
IIT Kanpur B.Cyber - Proof-of-Work Portfolio Submission

This script simulates periodic integrity scans of a critical enterprise directory.
It uses cryptographic SHA-256 hashing to detect file modifications and unauthorized
new files, all within Python's standard library (time, random, hashlib).
"""

import time
import random
import hashlib
import sys
from typing import Dict, List, Tuple

# ----------------------------------------------------------------------
# ANSI color codes for terminal output (glowing/flashing effects simulated)
# ----------------------------------------------------------------------
GREEN = "\033[92m"          # Bright green for OK
RED = "\033[91m"            # Bright red for WARNING
YELLOW = "\033[93m"         # Yellow for new files
RESET = "\033[0m"           # Reset to default
BOLD = "\033[1m"            # Bold for emphasis
# Flashing is not universally supported; we'll use bold + red instead.

# ----------------------------------------------------------------------
# Mock enterprise directory structure and baseline generation
# ----------------------------------------------------------------------
# List of critical system files (simulated paths)
MOCK_FILE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/system/bin/init",
    "/system/bin/sh",
    "/usr/lib/libc.so.6",
    "/var/log/auth.log",
]

# Predefined content for each mock file (to have deterministic baseline)
# In a real scenario, these would be read from disk.
INITIAL_CONTENTS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "/etc/shadow": "root:$6$xyz:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::",
    "/system/bin/init": "#!/bin/sh\n/sbin/init\n",
    "/system/bin/sh": "#!/bin/sh\necho 'Shell'\n",
    "/usr/lib/libc.so.6": "ELF header... (simulated library content)",
    "/var/log/auth.log": "Jan 1 00:00:00 host sshd[123]: Accepted password for root",
}

def generate_baseline() -> Dict[str, str]:
    """
    Compute SHA-256 hash for each mock file using its initial content.
    Returns a dictionary: path -> hash_hex.
    """
    baseline = {}
    for path, content in INITIAL_CONTENTS.items():
        sha = hashlib.sha256(content.encode('utf-8')).hexdigest()
        baseline[path] = sha
    return baseline

BASELINE_HASHES = generate_baseline()

# ----------------------------------------------------------------------
# Helper functions for simulating file system changes
# ----------------------------------------------------------------------

def random_content() -> str:
    """Generate a random string to simulate altered or new file content."""
    # Random length between 10 and 100 characters
    length = random.randint(10, 100)
    # Use random printable ASCII (letters, digits, punctuation)
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-= '
    return ''.join(random.choice(chars) for _ in range(length))

def generate_snapshot() -> Dict[str, str]:
    """
    Simulate the current state of the file system.
    - Start with all baseline files.
    - For each baseline file, with probability MODIFY_PROB, change its content.
    - With probability NEW_PROB, add a new file not in baseline.
    Returns a dictionary: path -> content (string).
    """
    MODIFY_PROB = 0.3   # 30% chance per file to be modified
    NEW_PROB = 0.2      # 20% chance to add a new file per scan

    # Start with a copy of the initial content
    snapshot = dict(INITIAL_CONTENTS)

    # Randomly modify existing files
    for path in list(snapshot.keys()):
        if random.random() < MODIFY_PROB:
            snapshot[path] = random_content()   # replace with random content

    # Randomly add new files (not in baseline)
    if random.random() < NEW_PROB:
        # Generate a plausible new path
        new_path = f"/opt/new_service/{random.randint(1000,9999)}.conf"
        # Avoid collision with existing baseline paths (unlikely)
        while new_path in snapshot:
            new_path = f"/opt/new_service/{random.randint(1000,9999)}.conf"
        snapshot[new_path] = random_content()

    return snapshot

def compute_hashes(snapshot: Dict[str, str]) -> Dict[str, str]:
    """
    Compute SHA-256 hash for each file in the snapshot.
    Returns dict: path -> hash_hex.
    """
    hashes = {}
    for path, content in snapshot.items():
        sha = hashlib.sha256(content.encode('utf-8')).hexdigest()
        hashes[path] = sha
    return hashes

def scan_integrity(baseline: Dict[str, str], snapshot_hashes: Dict[str, str]) -> List[Tuple[str, str, str]]:
    """
    Compare the snapshot hashes against the baseline.
    Returns a list of tuples: (path, status, hash_value)
    status: 'OK' if unchanged, 'MODIFIED' if changed, 'NEW' if new file.
    """
    results = []
    # Check all files in snapshot
    for path, current_hash in snapshot_hashes.items():
        if path in baseline:
            if current_hash == baseline[path]:
                status = "OK"
            else:
                status = "MODIFIED"
        else:
            status = "NEW"
        results.append((path, status, current_hash))
    return results

# ----------------------------------------------------------------------
# Output formatting functions
# ----------------------------------------------------------------------

def print_scan_header(iteration: int):
    """Print a header for each scan iteration."""
    print("\n" + "=" * 80)
    print(f"{BOLD}🔍 INTEGRITY SCAN ITERATION #{iteration}{RESET}")
    print("=" * 80)

def print_result_line(path: str, status: str, hash_val: str):
    """Print a single file's result with appropriate coloring."""
    if status == "OK":
        indicator = f"{GREEN}[OK - INTEGRITY SECURE]{RESET}"
    elif status == "MODIFIED":
        indicator = f"{RED}{BOLD}[WARNING - FILE MODIFIED / MALICIOUS TAMPER DETECTED]{RESET}"
    else:  # NEW
        indicator = f"{YELLOW}[INFO - NEW FILE CREATED (UNAUTHORIZED)]{RESET}"
    print(f"{indicator}  {path}")
    print(f"   SHA-256: {hash_val}")

def print_summary(results: List[Tuple[str, str, str]]):
    """Print summary counts per status."""
    counts = {"OK": 0, "MODIFIED": 0, "NEW": 0}
    for _, status, _ in results:
        counts[status] = counts.get(status, 0) + 1
    print(f"\nSummary: {GREEN}{counts['OK']} OK{RESET} | "
          f"{RED}{counts['MODIFIED']} MODIFIED{RESET} | "
          f"{YELLOW}{counts['NEW']} NEW{RESET}")

def print_final_metrics(all_results: List[List[Tuple[str, str, str]]]):
    """
    Print a beautiful ASCII table summarizing all scan iterations.
    all_results: list of results from each scan (each is a list of tuples).
    """
    print("\n\n" + "=" * 80)
    print(f"{BOLD}📊 FINAL SCAN CYCLE METRICS (OVERALL SUMMARY){RESET}")
    print("=" * 80)

    # Compute per-iteration counts and totals
    iterations = len(all_results)
    total_ok = total_mod = total_new = 0
    table_rows = []
    for i, results in enumerate(all_results, start=1):
        cnt_ok = sum(1 for _, s, _ in results if s == "OK")
        cnt_mod = sum(1 for _, s, _ in results if s == "MODIFIED")
        cnt_new = sum(1 for _, s, _ in results if s == "NEW")
        total_ok += cnt_ok
        total_mod += cnt_mod
        total_new += cnt_new
        table_rows.append((i, cnt_ok, cnt_mod, cnt_new))

    # Print ASCII table
    # Column headers
    print(f"\n{'Iteration':<12} | {'OK':<8} | {'Modified':<10} | {'New':<8}")
    print("-" * 48)
    for row in table_rows:
        print(f"{row[0]:<12} | {row[1]:<8} | {row[2]:<10} | {row[3]:<8}")
    print("-" * 48)
    print(f"{'TOTAL':<12} | {total_ok:<8} | {total_mod:<10} | {total_new:<8}")
    print("\n" + "=" * 80)

# ----------------------------------------------------------------------
# Main simulation loop
# ----------------------------------------------------------------------

def main():
    """
    Main entry point. Runs the integrity checker for a fixed number of scans.
    """
    print(f"{BOLD}🚀 SYSTEM INTEGRITY HASH CHECKER (FIM SIMULATOR){RESET}")
    print("Monitoring critical system files using SHA-256 cryptographic hashing.\n")

    baseline = BASELINE_HASHES
    print("Baseline hashes computed for:")
    for path, h in baseline.items():
        print(f"  {path} -> {h[:16]}...")
    print("\nStarting continuous integrity monitoring... (Ctrl+C to stop early)\n")

    SCAN_INTERVAL = 2   # seconds between scans
    MAX_SCANS = 5       # number of scan cycles before showing final metrics

    all_scan_results = []   # store results for final table

    try:
        for scan_num in range(1, MAX_SCANS + 1):
            print_scan_header(scan_num)

            # 1. Simulate current state
            snapshot = generate_snapshot()
            snapshot_hashes = compute_hashes(snapshot)

            # 2. Compare with baseline
            results = scan_integrity(baseline, snapshot_hashes)

            # 3. Display each file's status
            for path, status, h in results:
                print_result_line(path, status, h)

            # 4. Summary counts
            print_summary(results)

            # 5. Store for final metrics
            all_scan_results.append(results)

            # 6. Wait for next scan (if not last)
            if scan_num < MAX_SCANS:
                print(f"\n⏳ Waiting {SCAN_INTERVAL} seconds before next scan...")
                time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user. Generating final metrics from available data...")

    # Final metrics table
    if all_scan_results:
        print_final_metrics(all_scan_results)
    else:
        print("No scan data collected.")

    print("\n✅ Integrity monitoring simulation complete.")

if __name__ == "__main__":
    main()