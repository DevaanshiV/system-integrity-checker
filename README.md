# System Integrity Hash Checker (FIM Simulator)

A lightweight, production‑ready Python 3 script that simulates a **File Integrity Monitor (FIM)** for critical enterprise directories. It continuously validates cryptographic SHA‑256 hashes against a baseline, detects malicious file tampering, and reports unauthorized new files — all using only Python’s standard library. Designed for educational portfolios, sandbox environments, and security demonstration labs.

---

## 🔐 Cryptographic Validation Mechanics

The core integrity check relies on **SHA‑256** hash comparisons:

1. **Baseline Generation**  
   On startup, the script computes the SHA‑256 digest of each mock file’s static content (e.g., `/etc/passwd`). These digests form the immutable baseline dictionary.

2. **Periodic Snapshot & Re‑hashing**  
   At every scan interval, the current state of each file is re‑hashed using `hashlib.sha256()`. The new digest is compared with the stored baseline.

3. **Tamper Detection Logic**  
   - **File Unchanged** → digest matches baseline → `[OK - INTEGRITY SECURE]`  
   - **File Modified** → digest differs → `[WARNING - FILE MODIFIED / MALICIOUS TAMPER DETECTED]`  
   - **New File Created** → path not in baseline → `[INFO - NEW FILE CREATED (UNAUTHORIZED)]`

4. **Randomised Threat Simulation**  
   Each scan randomly modifies existing files or creates new ones with configurable probabilities (`MODIFY_PROB`, `NEW_PROB`), mimicking adversary activity without touching real files.

---

## 🛠️ Prerequisites

- **Python 3.6+** (uses only `time`, `random`, `hashlib`, `sys`, and `typing` – no external packages).
- Terminal with **ANSI colour support** (for coloured log output).
- No file system permissions, root access, or external storage required – runs entirely in memory.

---

## 📦 Installation

Clone the repository and navigate to the project folder:

```bash
git clone https://github.com/yourusername/system-integrity-hash-checker.git
cd system-integrity-hash-checker
