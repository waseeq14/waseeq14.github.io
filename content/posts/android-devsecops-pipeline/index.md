---
title: "I Built a Security Pipeline That Scans Every Android Build Automatically"
date: 2026-01-15
draft: false
tags: ["devsecops", "android", "jenkins", "aws", "mobsf", "ci-cd", "appsec"]
categories: ["Projects"]
description: "A walkthrough of why I built an automated Android DevSecOps pipeline and what it covers - from SAST to APK-level mobile analysis, all wired into a single vulnerability dashboard."
showToc: false
---

Most security work happens too late. Code ships, an APK gets published, and someone finds a hardcoded API key or an insecure TLS configuration weeks later. I wanted to see what it looked like to wire security directly into the build process - so I built a pipeline that does it automatically on every commit.

The result is a Jenkins-based DevSecOps pipeline deployed on AWS that runs six different security tools against an Android application: static code analysis, secrets scanning, dependency scanning, code quality gates, and full APK-level mobile security testing - all feeding into a centralized vulnerability dashboard.

Here's the quick breakdown of what runs on every build:

- **Semgrep** - static analysis with security rules against the source code
- **Gitleaks** - catches hardcoded secrets before they leave the repo
- **SonarQube** - code quality gates, security hotspots, and bug detection
- **Trivy** - scans the filesystem for vulnerable dependencies and CVEs
- **MobSF** - uploads the built APK and runs a full mobile security analysis via REST API
- **DefectDojo** - aggregates findings from all tools into a single trackable dashboard

The infrastructure runs across two EC2 instances - one for Jenkins and the build tools, one for the security services (MobSF, SonarQube, DefectDojo) - so scanning workloads don't compete with CI execution.

The most interesting part was wiring everything together via APIs rather than manual steps. Every scan result flows into DefectDojo automatically, which means you end up with a running history of findings across every build rather than a pile of one-off reports.

For the full architecture breakdown, pipeline stage details, and key learnings - including where things got tricky with resource contention and DefectDojo deduplication - check out the **[full project write-up](/projects/android-devsecops-pipeline/)**.
