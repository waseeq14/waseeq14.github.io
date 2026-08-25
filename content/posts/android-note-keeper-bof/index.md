---
title: "Overflowing a JNI Buffer to Hijack system() in an Android Native Library"
date: 2025-09-01
draft: false
tags: ["android", "buffer-overflow", "native", "jni", "ghidra", "exploitation", "mobile-hacking-labs", "note-keeper"]
categories: ["Mobile Hacking Labs"]
description: "Exploiting a native stack buffer overflow in Note Keeper's JNI code to overwrite a command buffer adjacent to the overflow target, achieving arbitrary command execution via system()."
showToc: true
---

This is my writeup for the **Note Keeper** Android challenge by [Mobile Hacking Labs](https://www.mobilehackinglab.com/) - one of the more interesting challenges in the lab since it gets into native code exploitation rather than the usual Java layer.

---

I found a native stack buffer overflow in the Note Keeper challenge that lets me control the command string passed to `system()` from the app's JNI code.

---

## Overview

The APK takes **Title** and **Content** as inputs, and passes the title to `parse()` - a native function defined in `libnotekeeper.so`.

![](9205b728312651901f15387037c3180c.png)
![](b9fe5254b241a9962b7a1827767cd013.png)

---

## Vulnerability

While poking around `MainActivity.parse()` in `libnotekeeper.so` I noticed it reads the Java title with `GetStringLength` / `GetStringChars` and copies the characters into a fixed `char resultBuf[100]`. Right next to it on the stack is a `char cmdBuf[500]` prefilled with the literal `Log "Note added at $(date)"`. The native code then calls `system(cmdBuf)`.

![](9966fc66c6d7404fb37a7d92567e6ad6.png)

Because there's no bounds check, giving a long title overwrites `resultBuf`'s boundary and starts writing into `cmdBuf`. In this build `resultBuf` and `cmdBuf` are adjacent with no gap, so it's trivial to corrupt the start of `cmdBuf`.

From the Ghidra stack frame:
- `resultBuffer` at `sp-0x2a4`
- `cmdBuffer` at `sp-0x240` (adjacent)

---

## Exploit

```python
payload = "A" * 100
payload += 'log -t mytag "SUIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"'
print(payload)
```

A title long enough to overflow `resultBuf` into `cmdBuf` changes the stored command into a `log` invocation. I proved this in the emulator - the injected message appeared in `adb logcat`.

![](27a21a30454ec268e9fe681345fff413.png)

**Primitive:** buffer overflow in native `parse()` → controlled bytes land in `cmdBuf` → `system()` executes the modified command.

I used the `log` command as a harmless demonstration that arbitrary command execution is possible end-to-end.
