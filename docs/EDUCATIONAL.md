# Educational Guide: Understanding FauxSSH

## Introduction for Researchers

FauxSSH serves as an example of **Deception Technology** powered by Generative AI. This document is intended for security researchers, educators, and students who want to explore how Large Language Models can be applied to honeypot design.

> [!NOTE]
> **Broader Context**: The field of honeypot research is vast, with many sophisticated tools like **Cowrie** (medium interaction) and highly complex kernel-level instrumentation. FauxSSH represents a specific experiment in using **Generative AI** content generation to simulate system responses, rather than relying on static emulation or full virtualization.

## Core Concepts

### 1. The "Uncanny Valley" of Honeypots
Traditional honeypots often fall into two categories:
*   **Low-Interaction**: Simple scripts that simulate open ports (e.g., answering "SSH-2.0" but failing login).
*   **High-Interaction**: Real systems (VMs) that allow attackers to compromise them. These are dangerous and resource-intensive.

**Limitation**: Attackers use scripts to detect Low-Interaction honeypots. If a command like `uname -a` returns a hardcoded string, the honeypot is identified.

### 2. An Alternative: Simulated High-Interaction
FauxSSH introduces a third category. It uses a **Large Language Model (LLM)** to *hallucinate* a realistic operating system. 
*   It has no real kernel.
*   It has no real filesystem.
*   It has no real network stack.

Yet, when you run `cat /proc/cpuinfo`, the AI generates a plausible response based on the context of "a Linux server".

## Architecture for Students

The system is composed of three main layers:

1.  **The Interface (Protocol Layer)**:
    *   Uses `paramiko` to speak the binary SSH language.
    *   It handles encryption and authentication (accepting any password except root).

2.  **The Brain (LLM Layer)**:
    *   When a command is received (e.g., `make clean`), it is not executed.
    *   It is sent to Google Gemini as a prompt: *"Reflect the output of `make clean` in a directory containing C source files."*
    *   The LLM generates the *output*, which is returned to the attacker.

3.  **The Memory (State Layer)**:
    *   To maintain illusion, the system tracks the "Current Working Directory" (CWD) and "Virtual Filesystem" (VFS).
    *   If an attacker runs `touch malicious.sh`, the system records that this file exists in the VFS. Future `ls` commands will show it, even though it's just an entry in a database.

## Suggested Experiments

If you are studying honeypots, try these experiments with FauxSSH:

### Experiment A: The Turing Test
*   **Goal**: Determine if a human attacker can distinguish FauxSSH from a real Ubuntu server within 5 minutes.
*   **Method**: Have a colleague log in without telling them it's a honeypot. Watch their commands. When do they realize?

### Experiment B: Payload Analysis
*   **Goal**: Observe how the honeypot handles file uploads.
*   **Method**: upload a benign test file using `scp`. Note that it is isolated in `data/uploaded_files` and never executed, even if you run `./payload`. The "execution" is just the LLM *pretending* to run it.

### Experiment C: Prompt Injection
*   **Goal**: Test the limits of the `SecurityFilter`.
*   **Method**: Try to convince the simulated shell to reveal its system prompt or ignore previous instructions. (Note: Please report findings responsibly!).

## 6. Analyzing the Data

To help researchers extract insights from the collected data, we provide a suite of analytic tools in `tools/analytics/`.

### Session Analysis & Replay
The `analyze.py` tool is the primary way to inspect sessions.

```bash
# List all captured sessions
python3 tools/analytics/analyze.py --sessions

# List all commands across all sessions
python3 tools/analytics/analyze.py --commands

# Replay a specific session (view all commands and output logic)
python3 tools/analytics/analyze.py --session-id <SESSION_ID>

# Filter commands by IP
python3 tools/analytics/analyze.py --ip <IP_ADDRESS>
```

### Upload Inspector (Malware Analysis)
Attackers often download payloads (scripts, binaries) to the honeypot. These are safely quarantined in the database. Use `inspect_uploads.py` to analyze them.

```bash
# List all uploaded files with their SHA256 hashes
python3 tools/analytics/inspect_uploads.py --list

# Export a malicious file for reverse engineering (e.g., in Ghidra)
python3 tools/analytics/inspect_uploads.py --export <IP> <USER> <PATH> --out malware_sample.bin
```
