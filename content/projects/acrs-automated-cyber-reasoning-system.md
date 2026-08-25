---
title: "ACRS - Automated Cyber Reasoning System"
date: 2026-01-20
draft: false
tags: ["fyp", "research", "llm", "fuzzing", "symbolic-execution", "sast", "klee", "afl++", "semgrep", "devsecops", "django", "react"]
description: "Final Year Project — an automated vulnerability discovery, analysis, and remediation framework combining static analysis, symbolic execution, fuzzing, and LLM reasoning into a single research-oriented pipeline."
showToc: true
---

## Demo

<div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; border-radius: 8px; margin-bottom: 2rem; border: 1px solid var(--purple-dark);">
  <iframe
    src="https://www.youtube.com/embed/ym0mpNBknpw"
    title="ACRS Demo"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
    allowfullscreen
    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;">
  </iframe>
</div>

**GitHub:** [github.com/waseeq14/ACRS](https://github.com/waseeq14/ACRS)

---

## Overview

ACRS (Automated Cyber Reasoning System) is our Final Year Project for BS Cyber Security at COMSATS University Islamabad. The project targets a hard, practical problem in security research: vulnerability discovery and triage at scale is slow, manual, and expensive. ACRS attempts to automate the full pipeline — from finding bugs in C/C++ source code to explaining crashes, generating fix candidates, and assessing live systems over SSH.

The framework deliberately avoids relying on a single detection technique. Instead, it chains together multiple methods — static analysis, symbolic execution, fuzzing, memory sanitization, and LLM reasoning — so each stage can catch what the others miss. Outputs are designed to assist analysts and students, not replace expert manual validation.

The system exposes a **React frontend** backed by a **Django REST API**, supporting two distinct operating modes:

1. **Analysis Mode** - source-code driven vulnerability assessment
2. **Pentesting Mode** - SSH-driven live host enumeration and assessment

---

## Core Techniques

| Technique | Tool | Purpose |
|-----------|------|---------|
| Static Analysis | Semgrep | Pattern-based vulnerability discovery across source |
| Symbolic Execution | KLEE | Path exploration and bug-triggering input generation |
| Segment-Based Symbolic Exec | KLEE (targeted) | Focused symbolic analysis on suspicious code regions |
| Coverage-Guided Fuzzing | AFL++ | Dynamic testing with crash artifact capture |
| Memory Safety Detection | AddressSanitizer | Catches buffer overflows, use-after-free, etc. during execution |
| Vulnerability Reasoning | LLM | Contextual interpretation and prioritization of findings |
| Fuzzing Seed Generation | LLM | Improves AFL++ initialization with semantically meaningful seeds |
| Crash Analysis | LLM | Translates crash artifacts into actionable explanations |
| Patch Generation | LLM | Proposes remediation code and mitigation guidance |
| SSH Enumeration | LinPEAS-based | Authorized remote host assessment |
| Exploitability Mapping | GTFOBins + Exploit-DB | Maps findings to known exploitation techniques |

---

## Operating Modes

### Analysis Mode

Analysis Mode focuses on source-level and execution-level software assessment. A typical run looks like this:

1. Submit C/C++ source code via the frontend dashboard
2. **Semgrep** runs pattern-based static checks using custom and community rule sets
3. **KLEE** performs symbolic execution to explore code paths and generate crash-triggering inputs
4. **Segment-based symbolic execution** focuses KLEE on regions flagged as suspicious by earlier stages
5. **AFL++** takes over for coverage-guided fuzzing, capturing crash artifacts
6. **ASan** instruments the execution environment to surface memory-safety violations
7. **LLM pipeline** processes all findings:
   - reasons over detected issues in context
   - generates fuzzing seeds to improve AFL++ coverage
   - interprets crash artifacts into readable explanations
   - proposes patches and exploit-path analyses

### Pentesting Mode

Pentesting Mode targets authorized Linux systems over SSH:

1. Provide SSH credentials for an authorized target host
2. ACRS connects and runs enumeration (LinPEAS-based workflow)
3. Findings are classified and summarized automatically
4. GTFOBins and Exploit-DB are queried to provide exploitability context
5. The LLM generates exploit suggestions and patch-oriented recommendations

> Pentesting Mode is intended for legally authorized environments only.

---

## Architecture

```
ACRS/
├── backend/
│   ├── api/                       # REST endpoints, models, report generation
│   ├── vulnerability_analysis/    # Analysis pipeline (Semgrep/KLEE/AFL++/ASan/LLM)
│   └── pentest/                   # SSH pentesting helpers and scripts
├── frontend/
│   └── src/                       # React UI — analysis and pentest flows
├── semgrep-rules/                 # Custom Semgrep rule sets
├── report-template.html           # HTML report template (analysis)
└── pentest-report-template.html   # HTML report template (pentesting)
```

The backend is a **Django REST API** that orchestrates all tool invocations and LLM calls. The frontend is a **React** SPA that drives analysis workflows, renders findings, and exports reports. The two communicate over a local HTTP interface during development and can be deployed independently.

**External toolchain dependencies:**

- `semgrep`
- `klee` + LLVM toolchain
- `afl-fuzz` (AFL++)
- `clang` with `-fsanitize=address` support

---

## Outputs and Artifacts

Every run produces a mix of machine-readable and human-readable artifacts:

- **Static analysis findings** - Semgrep-derived issues with descriptions and rule references
- **Symbolic execution artifacts** - KLEE-generated path conditions and bug-triggering inputs
- **Segment-focused symbolic analysis outputs** - targeted path exploration results
- **Fuzzing artifacts** - AFL++ queues, crash inputs, coverage stats
- **Crash analysis summaries** - LLM-assisted interpretation of crash artifacts
- **Patch suggestions** - LLM-generated remediation code for review
- **Exploit-path guidance** - context-aware suggestions for security reviewers
- **HTML reports** - generated via template endpoints for documentation and handoff

---

## Research Context

ACRS sits at the intersection of program analysis and applied AI for security. The LLM integration is not a gimmick — it handles the parts of vulnerability triage that rule-based tools struggle with: explaining *why* a crash matters, proposing *contextually appropriate* patches rather than generic ones, and generating fuzzing seeds that reflect actual input semantics rather than random bytes.

The combination of KLEE and AFL++ is intentional. Symbolic execution is exhaustive but slow; fuzzing is fast but coverage-limited. Chaining them — using symbolic execution to seed and guide fuzzing — achieves better path coverage than either alone.

A research paper documenting the methodology, evaluation, and results is in progress and will be linked here upon publication.

---

## Team

| Name | Student ID |
|------|-----------|
| Waseeq Ur Rehman | FA21-BCT-021 |
| Abdullah bin Aamir | FA21-BCT-002 |
| Adil Sheikh | FA21-BCT-001 |

BS Cyber Security, COMSATS University Islamabad — Final Year Project

---

## Ethical Use

ACRS is built for academic research, controlled cybersecurity experimentation, and authorized security testing. It should not be used against systems, applications, or networks without explicit permission. Generated patches and exploit paths should be validated by qualified reviewers before any operational use.
