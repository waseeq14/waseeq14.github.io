---
title: "One Hook to Bypass All: Defeating iOS Jailbreak Detection with Frida"
date: 2025-11-15
draft: false
tags: ["ios", "frida", "jailbreak-bypass", "radare2", "objection", "swift", "mobile-hacking-labs", "no-escape"]
categories: ["Mobile Hacking Labs"]
description: "Bypassing iOS jailbreak detection in No Escape by hooking the root isJailbroken() export with Frida, then using Objection to find the flag in memory."
showToc: true
---

This is my writeup for the **No Escape** iOS challenge by [Mobile Hacking Labs](https://www.mobilehackinglab.com/) - a quick but clean jailbreak detection bypass that demonstrates how fragile single-function guards really are.

---

## Overview

A simple jailbreak detection bypass challenge. I downloaded the IPA, extracted it, and analyzed the binary with radare2. A few jailbreak detection methods were found:

![](210d29dbd6c038c006dcfa5228db52fa.png)

All of them were called inside a single main detection function. I got its full mangled name using `nm`:

![](2d23ce3a8f91b78cec05c9b3a9355079.png)

---

## Frida Script

```js
const address = Module.findExportByName(null, "$s9No_Escape12isJailbrokenSbyF");

if (address) {
  console.log("[+] Found the function: ", address);
  console.log("[+] Hooking...");

  Interceptor.replace(address, new NativeCallback(() => {
    console.log("[+] Bypassed!");
    return 0;
  }, 'int', []));
}
```

---

## Flag

After bypassing the checks, the flag appears in the UI. I used Objection to scan memory directly rather than reading it off screen:

![](bc43cd756f38031bb41fbba9f3bd8d96.png)

`MHL{hidin9_in_p1@in_5i9h+}`
