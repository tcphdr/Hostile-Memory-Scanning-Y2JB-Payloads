(async function() {
    try {
        await log("[*] Starting /dev/null Probe...");
        if (typeof eboot_base === 'undefined') {
            await log("[-] eboot_base missing.");
            return;
        }
        1. OPEN /dev/null
        We need a guaranteed valid place to write data.
        var dev_null = alloc_string("/dev/null");
        var O_WRONLY = 1n;  Standard Unix Constant
        var fd = syscall(SYSCALL.open, dev_null, O_WRONLY);
        if (Number(fd) < 0) {
            await log("[-] Failed to open /dev/null. FD: " + fd);
            return;
        }
        await log("[+] Opened /dev/null on FD: " + fd);
        await log("[*] Scanning 2MB of libc for Readable Data...");
        2. THE SCAN LOOP
        We scan a larger range (2MB) because .text might be XOM (unreadable),
        but .data (variables) MUST be readable.
        var HITS = 0;
        var FIRST_ERROR = null;
        for (var offset = 0n; offset < 0x200000n; offset += 0x1000n) {
            var target = libc_base + offset;
            Try to write 1 byte from 'target' to the Black Hole
            var ret = syscall(SYSCALL.write, fd, target, 1n);
            if (ret === 1n) {
                SUCCESS: We found a readable page!
                If this is offset 0, XOM is OFF. 
                If this is offset 0x100000+, it's likely the Data Segment.
                await log("[+] READABLE PAGE @ Offset " + toHex(offset));
                HITS++;
                If we find too many, stop spamming
                if (HITS > 5) {
                    await log("[...] (Stopping log, found readable data)");
                    break;
                }
            } else {
                CAPTURE THE FIRST ERROR CODE
                if (FIRST_ERROR === null) FIRST_ERROR = ret;
            }
        }
        3. DIAGNOSTICS
        if (HITS === 0) {
            await log("[-] No readable pages found.");
            await log("[*] First Error Code: " + toHex(FIRST_ERROR));
            0xFFFFFFFFFFFFFFF2 = -14 (EFAULT) -> Valid FD, but Bad Address (XOM confirmed)
            0xFFFFFFFFFFFFFFF7 = -9  (EBADF)  -> Bad FD (Open failed silently?)
        }
        syscall(SYSCALL.close, fd);
        await log("[*] Scan Complete.");
    } catch (e) {
        await log("[-] JS Error: " + e.message);
    }
})();
