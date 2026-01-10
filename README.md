# Memory Scanning in Hostile Environments via `write()` (Y2JB Payloads)

## Overview

This repository contains a set of minimal **Y2JB payloads** designed to safely probe *hostile or protected memory regions* on the PS5 **without triggering crashes** in the YouTube application.

The payloads intentionally prioritize stability and simplicity with the goal to determine **which regions of process memory are readable** while maintaining execution continuity inside a hostile WebKit environment.

---

## Core Concept

Instead of directly dereferencing memory (which would immediately crash the app if the page is unreadable or XOM-protected), these payloads leverage the behavior of the **`write()` system call**.

On FreeBSD (and therefore PS5), `write()` copies data from user memory using the kernel’s `copyin()` mechanism. If the source address is unreadable, the kernel **fails gracefully** and returns an error rather than crashing the process.

This makes `write()` a safe and reliable oracle for memory readability.

---

## Why This Works

### Unsafe Approach (Direct Dereference)

```js
*(uint8_t*)addr
```

❌ Causes an immediate crash if `addr` points to unreadable or XOM-protected memory.

---

### Safe Approach (Kernel-Mediated Access)

```js
syscall(SYSCALL.write, fd, addr, 1n)
```

✅ If readable → returns `1`
❌ If unreadable → returns `-EFAULT`
✔️ Process remains alive

---

## High-Level Strategy

1. Open `/dev/null` as a guaranteed valid write target
2. Iterate through memory page-by-page
3. Attempt to write **1 byte** from each candidate address
4. Record pages that succeed as readable
5. Never dereference memory directly

---

## Example Execution Log

```
Executing payload...
[*] Starting /dev/null Probe...
[+] Opened /dev/null on FD: 17
[*] Scanning 2MB of libc for Readable Data...
[+] READABLE PAGE @ Offset 0x0000000000000000
[+] READABLE PAGE @ Offset 0x0000000000001000
[+] READABLE PAGE @ Offset 0x0000000000002000
[+] READABLE PAGE @ Offset 0x0000000000003000
[+] READABLE PAGE @ Offset 0x0000000000004000
[+] READABLE PAGE @ Offset 0x0000000000005000
[...] (Stopping log, found readable data)
[*] Scan Complete.
Executed successfully
Connection closed
```

---

## Implementation Walkthrough

### 1. Open `/dev/null`

A valid file descriptor is required for `write()` to operate. `/dev/null` is used because it is guaranteed to exist and safely discards all output.

```js
var dev_null = alloc_string("/dev/null");
var O_WRONLY = 1n;
var fd = syscall(SYSCALL.open, dev_null, O_WRONLY);
```

If this step fails, the payload aborts immediately.

---

### 2. Memory Scan Loop

The payload scans **2 MB** starting at `libc_base`, advancing in **4 KB (page-sized) increments**.

This range is intentionally large:

* `.text` may be XOM-protected and unreadable
* `.data` and related segments **must** remain readable

```js
for (var offset = 0n; offset < 0x200000n; offset += 0x1000n) {
    var target = libc_base + offset;
    var ret = syscall(SYSCALL.write, fd, target, 1n);

    if (ret === 1n) {
        log("[+] READABLE PAGE @ Offset " + toHex(offset));
    }
}
```

A successful return value indicates that the page is readable.

---

### 3. Error Semantics

Only one error condition is relevant:

* **`-EFAULT`**
  Returned when the address is unreadable
  ✔️ No crash
  ✔️ Scan continues safely

This behavior confirms unreadable or XOM-protected memory without destabilizing the process.

---

## Safety Characteristics

* No segmentation faults
* No exception propagation
* No app termination on invalid memory access
* No reliance on undefined behavior
* Safe for repeated or blind scanning

This technique enables **crash-free discovery of readable memory layouts** inside hostile WebKit-based environments.

--- 

## Not a Vulnerability

This is NOT a vulnerability.
At first glance, this technique may appear to represent a class of memory disclosure or policy bypass, it does not. The behavior leveraged here is an intentional and well-defined property of the FreeBSD kernel’s copyin() / copyout() mechanisms. No security boundary is crossed, and no kernel or userspace security policy is violated.
In a normal operating environment, write() may return EFAULT for a variety of reasons. In this context, however, the return value can be used pre-deterministically as a readability oracle:

```Readable memory → write() succeeds```
OR
```Unreadable or protected memory → write() returns EFAULT```

No crash occurs in either case, crucially, this does not grant access to protected memory contents, nor does it bypass XOM, ASLR, or kernel-enforced access controls. It merely allows userland code to distinguish between readable and unreadable regions without dereferencing them directly.
This approach is therefore best described as a safe memory probing technique, not a vulnerability or exploit primitive. It relies entirely on documented kernel behavior and operates fully within the constraints imposed by the operating system.

---

## Requirements

* **Y2JB for PS5**
  [https://github.com/Gezine/Y2JB](https://github.com/Gezine/Y2JB)

---
