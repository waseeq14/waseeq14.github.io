---
title: "DVRN - Damn Vulnerable React Native"
date: 2026-02-10
draft: false
tags:
  [
    "react-native",
    "mobile-security",
    "hermes",
    "frida",
    "reverse-engineering",
    "android",
    "vulnerable-app",
    "ctf",
  ]
description: "A deliberately vulnerable React Native app built to teach RN-specific mobile security testing — three build variants (JSC, older Hermes, newer Hermes) demonstrating five real vulnerabilities and how their exploitation techniques change depending on how the target app was compiled."
showToc: true
---

**GitHub:** [github.com/waseeq14/DVRN](https://github.com/waseeq14/DVRN)

**Blog series:**

- Part 1 - [Understanding React Native Apps: A Pentester's Field Guide](/posts/react-native-pentesting-fundamentals/)
- Part 2 - [Exploiting React Native Apps: A Hands-On Walkthrough with DVRN](/posts/react-native-pentesting-with-dvrn/)

---

## Overview

DVRN (Damn Vulnerable React Native) is a deliberately vulnerable mobile app I built to have a real, hands-on target for teaching React Native-specific security testing — not generic mobile hardening checks any Android or iOS app could have, but bugs that are either unique to how React Native itself is built, or meaningfully different to exploit because of its architecture.

The project started from a gap I kept running into on real engagements: most public guidance on testing React Native apps stops at "extract the bundle and read it," and doesn't go into what happens once the bundle is compiled Hermes bytecode instead of plain JavaScript, or into the specific ways the JS-to-native bridge gets misused in real apps. DVRN and its accompanying two-part blog series exist to close that gap with concrete, personally verified techniques.

---

## Why three build variants?

The same JS-layer vulnerability requires a completely different exploitation technique depending on how the app's JavaScript was compiled. DVRN ships as three separate builds to demonstrate all three real-world cases:

| Variant       | Engine                | What it demonstrates                                                                              |
| ------------- | --------------------- | ------------------------------------------------------------------------------------------------- |
| **Variant A** | JSC (Hermes disabled) | Plain, readable JS bundle - direct static patching                                                |
| **Variant B** | Hermes, HBC89         | Bytecode with working disassemble/reassemble tooling                                              |
| **Variant C** | Hermes, HBC96         | Bytecode where no reassembler was available at the time of testing - runtime interception instead |

Same five vulnerabilities, identical logic, implemented across all three - only the _technique_ needed to exploit two of them changes. That's the entire premise of the project: pick a real target, and the right approach depends entirely on how it happens to be compiled.

---

## The five vulnerabilities

| ID    | Vulnerability                                                      | Applies to                                                      |
| ----- | ------------------------------------------------------------------ | --------------------------------------------------------------- |
| VB-01 | Insecure local storage - plaintext session token in `AsyncStorage` | All three variants (identical)                                  |
| VB-02 | Hardcoded secret in the JS bundle                                  | All three variants (identical)                                  |
| VB-04 | Exposed native module with no input validation                     | All three variants (identical)                                  |
| VB-03 | Client-side authorization bypass                                   | All three variants, **three different exploitation techniques** |
| VB-05 | Insecure WebView bridge                                            | All three variants (identical)                                  |

VB-03 is the flagship of the project - a client-side-only `isPremium` check that gets bypassed via a direct bundle patch on Variant A, a full disassemble/patch/reassemble cycle against real Hermes bytecode on Variant B, and live network interception (no bundle or source ever touched) on Variant C. Full exploitation walkthroughs, including the dead ends that came before each working technique, are in Part 2 of the blog series.

---

## Original tooling produced along the way

Building and exploiting Variant B specifically required real, original tooling work, not just following an existing guide:

- **HBC89 bytecode reassembly** had no working public tool at the start of this project. The most complete existing fork had a fatal reassembler bug (crashing on any function with an empty body, which every real Hermes bundle has). A different fork had already fixed that exact bug but didn't support HBC89. The working solution merges the two - available at [github.com/waseeq14/hbctool-add-vers-o-90](https://github.com/waseeq14/hbctool-add-vers-o-90).
- **A network-traffic-tracing Frida technique** for Variant C, developed after a JSI-level approach (hooking Hermes's internal call dispatcher) turned out to be impractical against a stripped release binary. Hooking React Native's own `ResponseUtil`/`NetworkingModule` classes gives a live view of network traffic without a proxy and without touching TLS at all - useful well beyond this one vulnerability.

Both are documented in full, including what didn't work first, in Part 2.

---

## Repo structure

Full source is included for all three variants - DVRN isn't a black-box challenge, it's meant to be read, patched, and rebuilt.

```
DVRN/
├── backend/            Shared Express.js backend - all three variants use this
├── scripts/             Frida scripts referenced in the blog series, ready to run
├── variant-a-no-hermes/
├── variant-b-old-hermes/
└── variant-c-new-hermes/
```

Pre-built release APKs for all three variants are available under [GitHub Releases](https://github.com/waseeq14/DVRN/releases) if you'd rather test than build.

---

## Scope

DVRN deliberately does not cover SSL pinning bypass, root/jailbreak detection bypass, or other generic mobile-hardening checks. Those aren't specific to React Native, and they're already well covered by existing vulnerable apps like AndroGoat and DVAA. DVRN's scope stays narrow on purpose: vulnerabilities that actually depend on React Native's own architecture.

---

## What's next

Everything in DVRN and the blog series is scoped to React Native's old bridge architecture. A similar project covering the new architecture - JSI, Fabric, TurboModules, and whatever the equivalent of "bridge interception" turns out to be once there's no bridge left to intercept - is next on the roadmap.
