# PS5 Userland Memory Dumper

## Overview
A userland JavaScript payload that leverages `query_memory_protection` (syscall `0x223`) to safely walk the PS5 virtual address space and stream all readable memory regions over TCP to a remote listener — without crashing the process. At its core this is an **oracle-driven memory scanner**: rather than blindly reading addresses and risking a fault, it interrogates each region's protection flags before touching its contents, allowing the payload to silently skip over unmapped, guard, and XOM (Execute-Only Memory) pages that would otherwise kill the process.

---

## The Oracle Approach

The key insight behind this dumper is that **reading an address and asking if an address is readable are two fundamentally different operations.** Direct `read8()` against an unmapped or XOM page causes an immediate fault with no recovery. `query_memory_protection` on the other hand returns the full descriptor of any virtual memory region — including its bounds, protection flags, and type metadata — without ever touching the data inside it.

This means the scanner can:
- Determine whether a region is safe to read *before* committing to it
- Skip entire classes of pages (XOM, guard, unmapped) cleanly
- Advance past holes in the address space using a tunable gap counter rather than crashing into them

This is the same class of technique used by `/dev/null`-oracle probing but implemented at the syscall metadata layer rather than the fault-recovery layer, making it considerably more stable across large address space walks.

---

## How It Works

### 1. Module Enumeration
Syscall `0x250` (`dynlib_get_list`) retrieves all currently loaded dynamic modules from the PS5 userland linker. For each module handle, syscall `0x251` (`dynlib_get_info`) fetches its metadata block, pulling the base load address and ASCII name string out of the info buffer at known offsets.

### 2. Region Walking (`scan_target`)
Starting from each module's base address, the scanner calls `query_memory_protection` page-by-page. Each successful call returns a region descriptor covering:
- `base` / `end` — the full bounds of the contiguous region
- `prot` — page protection flags (read, write, execute, XOM, etc.)
- `type_flags` — memory type metadata

The scanner advances `addr` to `r_end` after each mapped region, skipping the entire described range in one step rather than walking it page-by-page. For unmapped returns (negative signed result), it accumulates gap distance and only increments the `gap_runs` counter after `UNMAPPED_SKIP` bytes of consecutive unmapped space — this prevents a single sparse hole from prematurely aborting a module scan. After `MAX_GAP_RUNS` consecutive gap blocks the scanner gives up on that module and moves on.

### 3. Readable Region Filtering
Only regions whose protection flags fall within `READABLE_PROTS` (`0x1`, `0x3`, `0x11`, `0x13`) are selected for streaming. XOM pages (`0x4`) and write-only or otherwise unreadable regions are silently skipped — the process never attempts to read them.

### 4. Data Streaming
Selected regions are read and sent in `0x400`-byte chunks via `syscall(SYSCALL.write)` directly to the open socket. If a chunk write returns an error mid-stream (stale mapping, race, etc.), a zeroed buffer of the same size is substituted to keep the receiver's byte offsets consistent.

---

# Requirements
Y2JB framework by Gezine https://github.com/Gezine/Y2JB

---
