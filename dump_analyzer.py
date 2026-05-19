#!/usr/bin/env python3
import argparse
import os
import re
import struct
import string
from concurrent.futures import ProcessPoolExecutor, as_completed

try:
    import capstone
    CS_AVAILABLE = True
except ImportError:
    CS_AVAILABLE = False

MAGIC          = 0xDEADBEEF
EBOOT_BASE     = 0x4949c000
LIBKERNEL_BASE = 0x82bac0000
LIBC_BASE      = 0x9f7f8000
PROC_SIGNATURE = b"\xce\xfa\xef\xbe\xcc\xbb"

PROT_LABELS = {
    0x0:  "NONE",
    0x1:  "READ",
    0x3:  "READ|WRITE",
    0x4:  "EXEC(XOM)",
    0x11: "READ|EXEC",
    0x13: "READ|WRITE|EXEC",
}

SYSCALL_TABLE = {
    0x000: "syscall",               0x001: "exit",
    0x002: "fork",                  0x003: "read",
    0x004: "write",                 0x005: "open",
    0x006: "close",                 0x007: "wait4",
    0x009: "link",                  0x00a: "unlink",
    0x00c: "chdir",                 0x00d: "fchdir",
    0x00e: "mknod",                 0x00f: "chmod",
    0x010: "chown",                 0x014: "getpid",
    0x015: "mount",                 0x016: "unmount",
    0x017: "setuid",                0x018: "getuid",
    0x019: "geteuid",               0x01a: "ptrace",
    0x01b: "recvmsg",               0x01c: "sendmsg",
    0x01d: "recvfrom",              0x01e: "accept",
    0x01f: "getpeername",           0x020: "getsockname",
    0x021: "access",                0x022: "chflags",
    0x023: "fchflags",              0x024: "sync",
    0x025: "kill",                  0x027: "getppid",
    0x029: "dup",                   0x02a: "pipe",
    0x02b: "getegid",               0x02f: "getgid",
    0x031: "getlogin",              0x032: "setlogin",
    0x035: "sigaltstack",           0x036: "ioctl",
    0x037: "reboot",                0x038: "revoke",
    0x039: "symlink",               0x03a: "readlink",
    0x03b: "execve",                0x03c: "umask",
    0x03d: "chroot",                0x041: "msync",
    0x049: "munmap",                0x04a: "mprotect",
    0x04b: "madvise",               0x04e: "mincore",
    0x04f: "getgroups",             0x050: "setgroups",
    0x051: "getpgrp",               0x052: "setpgid",
    0x053: "setitimer",             0x056: "getitimer",
    0x059: "getdtablesize",         0x05a: "dup2",
    0x05c: "fcntl",                 0x05d: "select",
    0x05f: "fsync",                 0x060: "setpriority",
    0x061: "socket",                0x062: "connect",
    0x063: "netcontrol",            0x064: "getpriority",
    0x065: "netabort",              0x066: "netgetsockinfo",
    0x068: "bind",                  0x069: "setsockopt",
    0x06a: "listen",                0x074: "gettimeofday",
    0x075: "getrusage",             0x076: "getsockopt",
    0x078: "readv",                 0x079: "writev",
    0x07a: "settimeofday",          0x07b: "fchown",
    0x07c: "fchmod",                0x07d: "netgetiflist",
    0x07e: "setreuid",              0x07f: "setregid",
    0x080: "rename",                0x083: "flock",
    0x085: "sendto",                0x086: "shutdown",
    0x087: "socketpair",            0x088: "mkdir",
    0x089: "rmdir",                 0x08a: "utimes",
    0x08c: "adjtime",               0x08d: "kqueueex",
    0x093: "setsid",                0x0a5: "sysarch",
    0x0bc: "stat",                  0x0bd: "fstat",
    0x0be: "lstat",                 0x0bf: "pathconf",
    0x0c0: "fpathconf",             0x0c2: "getrlimit",
    0x0c3: "setrlimit",             0x0c4: "getdirentries",
    0x0ca: "__sysctl",              0x0cb: "mlock",
    0x0cc: "munlock",               0x0ce: "futimes",
    0x0cf: "getpgid",               0x0d1: "poll",
    0x0e8: "clock_gettime",         0x0e9: "clock_settime",
    0x0ea: "clock_getres",          0x0eb: "ktimer_create",
    0x0ec: "ktimer_delete",         0x0ed: "ktimer_settime",
    0x0ee: "ktimer_gettime",        0x0ef: "ktimer_getoverrun",
    0x0f0: "nanosleep",             0x0fa: "minherit",
    0x0fb: "rfork",                 0x0fd: "issetugid",
    0x0fe: "lchown",                0x110: "getdents",
    0x121: "preadv",                0x122: "pwritev",
    0x136: "getsid",                0x13b: "aio_suspend",
    0x141: "yield",                 0x144: "mlockall",
    0x145: "munlockall",            0x146: "__getcwd",
    0x147: "sched_setparam",        0x148: "sched_getparam",
    0x149: "sched_setscheduler",    0x14a: "sched_getscheduler",
    0x14b: "sched_yield",           0x14c: "sched_get_priority_max",
    0x14d: "sched_get_priority_min",0x14e: "sched_rr_get_interval",
    0x154: "sigprocmask",           0x155: "sigsuspend",
    0x157: "sigpending",            0x159: "sigtimedwait",
    0x15a: "sigwaitinfo",           0x16a: "kqueue",
    0x16b: "kevent",                0x188: "uuidgen",
    0x189: "sendfile",              0x18b: "getfsstat",
    0x18c: "statfs",                0x18d: "fstatfs",
    0x190: "ksem_close",            0x191: "ksem_post",
    0x192: "ksem_wait",             0x193: "ksem_trywait",
    0x194: "ksem_init",             0x195: "ksem_open",
    0x196: "ksem_unlink",           0x197: "ksem_getvalue",
    0x198: "ksem_destroy",          0x1a0: "sigaction",
    0x1a1: "sigreturn",             0x1a5: "getcontext",
    0x1a6: "setcontext",            0x1a7: "swapcontext",
    0x1ad: "sigwait",               0x1ae: "thr_create",
    0x1af: "thr_exit",              0x1b0: "thr_self",
    0x1b1: "thr_kill",              0x1b9: "ksem_timedwait",
    0x1ba: "thr_suspend",           0x1bb: "thr_wake",
    0x1bc: "kldunloadf",            0x1c6: "_umtx_op",
    0x1c7: "thr_new",               0x1c8: "sigqueue",
    0x1d0: "thr_set_name",          0x1d2: "rtprio_thread",
    0x1db: "pread",                 0x1dc: "pwrite",
    0x1dd: "mmap",                  0x1de: "lseek",
    0x1df: "truncate",              0x1e0: "ftruncate",
    0x1e1: "thr_kill2",             0x1e2: "shm_open",
    0x1e3: "shm_unlink",            0x1e6: "cpuset_getid",
    0x1e7: "cpuset_getaffinity",    0x1e8: "cpuset_setaffinity",
    0x1ea: "fchmodat",              0x1eb: "fchownat",
    0x1ed: "fstatat",               0x1ee: "futimesat",
    0x1ef: "linkat",                0x1f0: "mkdirat",
    0x1f3: "openat",                0x1f5: "renameat",
    0x1f6: "symlinkat",             0x1f7: "unlinkat",
    0x1fe: "__semctl",              0x1ff: "msgctl",
    0x200: "shmctl",                0x203: "__cap_rights_get",
    0x20a: "pselect",               0x214: "regmgr_call",
    0x215: "jitshm_create",         0x216: "jitshm_alias",
    0x217: "dl_get_list",           0x218: "dl_get_info",
    0x21a: "evf_create",            0x21b: "evf_delete",
    0x21c: "evf_open",              0x21d: "evf_close",
    0x21e: "evf_wait",              0x21f: "evf_trywait",
    0x220: "evf_set",               0x221: "evf_clear",
    0x222: "evf_cancel",            0x223: "query_memory_protection",
    0x224: "batch_map",             0x225: "osem_create",
    0x226: "osem_delete",           0x227: "osem_open",
    0x228: "osem_close",            0x229: "osem_wait",
    0x22a: "osem_trywait",          0x22b: "osem_post",
    0x22c: "osem_cancel",           0x22d: "namedobj_create",
    0x22e: "namedobj_delete",       0x22f: "set_vm_container",
    0x230: "debug_init",            0x231: "suspend_process",
    0x232: "resume_process",        0x233: "opmc_enable",
    0x234: "opmc_disable",          0x235: "opmc_set_ctl",
    0x236: "opmc_set_ctr",          0x237: "opmc_get_ctr",
    0x238: "budget_create",         0x239: "budget_delete",
    0x23a: "budget_get",            0x23b: "budget_set",
    0x23c: "virtual_query",         0x23d: "mdbg_call",
    0x249: "is_in_sandbox",         0x24a: "dmem_container",
    0x24b: "get_authinfo",          0x24c: "mname",
    0x24f: "dynlib_dlsym",          0x250: "dynlib_get_list",
    0x251: "dynlib_get_info",       0x252: "dynlib_load_prx",
    0x253: "dynlib_unload_prx",     0x254: "dynlib_do_copy_relocations",
    0x256: "dynlib_get_proc_param", 0x257: "dynlib_process_needed_and_relocate",
    0x258: "sandbox_path",          0x259: "mdbg_service",
    0x25a: "randomized_path",       0x25b: "rdup",
    0x25c: "dl_get_metadata",       0x25d: "workaround8849",
    0x25e: "is_development_mode",   0x25f: "get_self_auth_info",
    0x260: "dynlib_get_info_ex",    0x261: "budget_getid",
    0x262: "budget_get_ptype",      0x263: "get_paging_stats_of_all_threads",
    0x264: "get_proc_type_info",    0x265: "get_resident_count",
    0x266: "prepare_to_suspend_process", 0x267: "get_resident_fmem_count",
    0x268: "thr_get_name",          0x269: "set_gpo",
    0x26a: "get_paging_stats_of_all_objects", 0x26b: "test_debug_rwmem",
    0x26c: "free_stack",            0x26d: "suspend_system",
    0x26e: "ipmimgr_call",          0x26f: "get_gpo",
    0x270: "get_vm_map_timestamp",  0x271: "opmc_set_hw",
    0x272: "opmc_get_hw",           0x273: "get_cpu_usage_all",
    0x274: "mmap_dmem",             0x275: "physhm_open",
    0x276: "physhm_unlink",         0x278: "thr_suspend_ucontext",
    0x279: "thr_resume_ucontext",   0x27a: "thr_get_ucontext",
    0x27b: "thr_set_ucontext",      0x27c: "set_timezone_info",
    0x27d: "set_phys_fmem_limit",   0x27e: "utc_to_localtime",
    0x27f: "localtime_to_utc",      0x280: "set_uevt",
    0x281: "get_cpu_usage_proc",    0x282: "get_map_statistics",
    0x283: "set_chicken_switches",  0x286: "get_kernel_mem_statistics",
    0x287: "get_sdk_compiled_version", 0x288: "app_state_change",
    0x289: "dynlib_get_obj_member", 0x28c: "process_terminate",
    0x28d: "blockpool_open",        0x28e: "blockpool_map",
    0x28f: "blockpool_unmap",       0x290: "dynlib_get_info_for_libdbg",
    0x291: "blockpool_batch",       0x292: "fdatasync",
    0x293: "dynlib_get_list2",      0x294: "dynlib_get_info2",
    0x295: "aio_submit",            0x296: "aio_multi_delete",
    0x297: "aio_multi_wait",        0x298: "aio_multi_poll",
    0x299: "aio_get_data",          0x29a: "aio_multi_cancel",
    0x29b: "get_bio_usage_all",     0x29c: "aio_create",
    0x29d: "aio_submit_cmd",        0x29e: "aio_init",
    0x29f: "get_page_table_stats",  0x2a0: "dynlib_get_list_for_libdbg",
    0x2a1: "blockpool_move",        0x2a2: "virtual_query_all",
    0x2a3: "reserve_2mb_page",      0x2a4: "cpumode_yield",
    0x2a5: "wait6",                 0x2a6: "cap_rights_limit",
    0x2a7: "cap_ioctls_limit",      0x2a8: "cap_ioctls_get",
    0x2a9: "cap_fcntls_limit",      0x2aa: "cap_fcntls_get",
    0x2ab: "bindat",                0x2ac: "connectat",
    0x2ad: "chflagsat",             0x2ae: "accept4",
    0x2af: "pipe2",                 0x2b0: "aio_mlock",
    0x2b1: "procctl",               0x2b2: "ppoll",
    0x2b3: "futimens",              0x2b4: "utimensat",
    0x2b5: "numa_getaffinity",      0x2b6: "numa_setaffinity",
    0x2bc: "apr_submit",            0x2bd: "apr_resolve",
    0x2be: "apr_stat",              0x2bf: "apr_wait",
    0x2c0: "apr_ctrl",              0x2c1: "get_phys_page_size",
    0x2c2: "begin_app_mount",       0x2c3: "end_app_mount",
    0x2c4: "fsc2h_ctrl",            0x2c5: "streamwrite",
    0x2c6: "app_save",              0x2c7: "app_restore",
    0x2c8: "saved_app_delete",      0x2c9: "get_ppr_sdk_compiled_version",
    0x2ca: "notify_app_event",      0x2cb: "ioreq",
    0x2cc: "openintr",              0x2cd: "dl_get_info_2",
    0x2ce: "acinfo_add",            0x2cf: "acinfo_delete",
    0x2d0: "acinfo_get_all_for_coredump", 0x2d1: "ampr_ctrl_debug",
    0x2d2: "workspace_ctrl",
}

STRING_KEYWORDS = [
    "password", "secret", "key", "token", "auth", "cred",
    "kernel", "syscall", "exploit", "dlsym", "mmap", "root",
    "uid=0", "/dev/", "sqlite", "webkit", "http", "https",
    "certificate", "private", "sign", ".sprx", ".prx",
]

CRYPTO_MARKERS = {
    b"\x30\x82":          "DER sequence (cert/key)",
    b"-----BEGIN":        "PEM header",
    b"-----END":          "PEM footer",
    b"\x00\x01\x00\x01": "RSA public exponent (65537)",
    b"AES":               "AES string ref",
    b"SHA256":            "SHA256 string ref",
    b"HMAC":              "HMAC string ref",
}

GENERAL_MARKERS = {
    b"libSceWebKit":                      "WebKit (userland)",
    b"bnet_netevent":                     "Kernel memory fragment",
    b"sys_netcontrol":                    "Kernel memory fragment",
    b"sceKernelAllocateMainDirectMemory": "Kernel alloc string",
    b"allproc":                           "allproc symbol",
    b"f_count":                           "file struct hint",
    b"p_ucred":                           "ucred marker",
}

JOP_DISPATCHERS = [
    (re.compile(b'\xff\xe0'),           "jmp rax"),
    (re.compile(b'\xff\xe1'),           "jmp rcx"),
    (re.compile(b'\xff\xe2'),           "jmp rdx"),
    (re.compile(b'\xff\xe3'),           "jmp rbx"),
    (re.compile(b'\xff\xe6'),           "jmp rsi"),
    (re.compile(b'\xff\xe7'),           "jmp rdi"),
    (re.compile(b'\xff\xd0'),           "call rax"),
    (re.compile(b'\xff\xd1'),           "call rcx"),
    (re.compile(b'\xff\xd7'),           "call rdi"),
    (re.compile(b'\xff\x20'),           "jmp [rax]"),
    (re.compile(b'\xff\x21'),           "jmp [rcx]"),
    (re.compile(b'\xff\x23'),           "jmp [rbx]"),
    (re.compile(b'\xff\x27'),           "jmp [rsp]"),
    (re.compile(b'\xff\x60.', re.DOTALL),       "jmp [rax+disp8]"),
    (re.compile(b'\xff\x63.', re.DOTALL),       "jmp [rbx+disp8]"),
    (re.compile(b'\xff\x67.', re.DOTALL),       "jmp [rdi+disp8]"),
    (re.compile(b'\x41\xff\xe0'),       "jmp r8"),
    (re.compile(b'\x41\xff\xe1'),       "jmp r9"),
    (re.compile(b'\x41\xff\xe3'),       "jmp r11"),
    (re.compile(b'\x41\xff\x20'),       "jmp [r8]"),
    (re.compile(b'\x41\xff\x23'),       "jmp [r11]"),
    (re.compile(b'\x48\xff\x27'),       "jmp [rsp]  (REX.W)"),
    (re.compile(b'\xff\xa4\x24....', re.DOTALL), "jmp [rsp+disp32]"),
]

COP_PATTERNS = [
    (re.compile(b'\xff\x10'),           "call [rax]"),
    (re.compile(b'\xff\x11'),           "call [rcx]"),
    (re.compile(b'\xff\x13'),           "call [rbx]"),
    (re.compile(b'\xff\x16'),           "call [rsi]"),
    (re.compile(b'\xff\x17'),           "call [rdi]"),
    (re.compile(b'\xff\x50.', re.DOTALL),       "call [rax+disp8]"),
    (re.compile(b'\xff\x53.', re.DOTALL),       "call [rbx+disp8]"),
    (re.compile(b'\xff\x57.', re.DOTALL),       "call [rdi+disp8]"),
    (re.compile(b'\x41\xff\x10'),       "call [r8]"),
    (re.compile(b'\x41\xff\x13'),       "call [r11]"),
    (re.compile(b'\x41\xff\x50.', re.DOTALL),   "call [r8+disp8]"),
]

VTABLE_PATTERNS = [
    re.compile(b'\x48\x8b\x07\xff\x20'),
    re.compile(b'\x48\x8b\x06\xff\x20'),
    re.compile(b'\x48\x8b\x03\xff\x20'),
    re.compile(b'\x48\x8b\x07\xff\x10'),
    re.compile(b'\x48\x8b\x07\x48\x8b\x40.\xff\xd0', re.DOTALL),
    re.compile(b'\x48\x8b\x07\x48\x8b\x40.\xff\xe0', re.DOTALL),
]

SYSCALL_DISPATCH_PATTERNS = [
    re.compile(b'\x48\x8d\x05....\x0f\x05', re.DOTALL),
    re.compile(b'\xff\x14\xc5....\x0f\x05', re.DOTALL),
    re.compile(b'\x49\x89\xca\x0f\x05'),
    re.compile(b'\x0f\x05.{0,4}\x0f\x05', re.DOTALL),
]

def prot_str(p):
    return PROT_LABELS.get(p, f"0x{p:x}")

def parse_regions(data):
    regions, i = [], 0
    while i < len(data) - 0x30:
        if struct.unpack_from("<I", data, i)[0] != MAGIC:
            i += 1
            continue
        name      = data[i+0x20:i+0x28].rstrip(b'\x00').decode('utf-8', errors='replace')
        base      = struct.unpack_from("<Q", data, i+0x08)[0]
        end       = struct.unpack_from("<Q", data, i+0x10)[0]
        prot      = struct.unpack_from("<I", data, i+0x18)[0]
        type_flag = struct.unpack_from("<I", data, i+0x1c)[0]
        i        += 0x30
        size      = end - base
        regions.append({"name": name, "base": base, "end": end,
                        "prot": prot, "type": type_flag, "data": data[i:i+size]})
        i += size
    return regions

def split_regions(regions, out_dir, filename):
    os.makedirs(out_dir, exist_ok=True)
    lines = []
    for r in regions:
        fname = os.path.join(out_dir,
            f"{filename}_{hex(r['base'])}_{hex(r['end'])}_prot{hex(r['prot'])}.bin")
        with open(fname, "wb") as f:
            f.write(r["data"])
        lines.append(f"  [+] {fname} ({len(r['data'])/1024:.1f} KB)")
    return lines

def extract_strings(data, min_len=6):
    printable = set(string.printable.encode()) - {0x0a, 0x0d, 0x09}
    results, current, start = [], [], 0
    for offset, byte in enumerate(data):
        if byte in printable:
            if not current:
                start = offset
            current.append(byte)
        else:
            if len(current) >= min_len:
                results.append((start, bytes(current).decode('ascii', errors='replace')))
            current = []
    if len(current) >= min_len:
        results.append((start, bytes(current).decode('ascii', errors='replace')))
    return results

def extract_strings_utf16(data, min_len=6):
    results = []
    i = 0
    while i < len(data) - 2:
        if data[i+1] == 0 and 0x20 <= data[i] < 0x7f:
            start = i
            chars = []
            while i < len(data) - 1 and data[i+1] == 0 and 0x20 <= data[i] < 0x7f:
                chars.append(chr(data[i]))
                i += 2
            s = ''.join(chars)
            if len(s) >= min_len:
                results.append((start, s))
        else:
            i += 1
    return results

def disasm_seq_fallback(buf, base=0):
    REG64  = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"]
    REG64X = ["r8","r9","r10","r11","r12","r13","r14","r15"]
    insns, i = [], 0
    while i < len(buf):
        b = buf[i]
        if b in (0xc3, 0xcb):
            insns.append((base+i, "ret")); i += 1; break
        elif b == 0xc9:
            insns.append((base+i, "leave")); i += 1
        elif b == 0x90:
            insns.append((base+i, "nop")); i += 1
        elif buf[i:i+3] == b'\x0f\x1f\x00':
            insns.append((base+i, "nop dword [rax]")); i += 3
        elif buf[i:i+4] == b'\x0f\x1f\x40\x00':
            insns.append((base+i, "nop dword [rax+0]")); i += 4
        elif buf[i:i+3] == b'\x66\x66\x90':
            insns.append((base+i, "nop (multi)")); i += 3
        elif b == 0x66 and i+1 < len(buf) and buf[i+1] == 0x90:
            insns.append((base+i, "nop (66)")); i += 2
        elif b == 0x0f and i+1 < len(buf) and buf[i+1] == 0x05:
            insns.append((base+i, "syscall")); i += 2
        elif 0x50 <= b <= 0x57:
            insns.append((base+i, f"push {REG64[b-0x50]}")); i += 1
        elif 0x58 <= b <= 0x5f:
            insns.append((base+i, f"pop {REG64[b-0x58]}")); i += 1
        elif b == 0x41 and i+1 < len(buf) and 0x50 <= buf[i+1] <= 0x57:
            insns.append((base+i, f"push {REG64X[buf[i+1]-0x50]}")); i += 2
        elif b == 0x41 and i+1 < len(buf) and 0x58 <= buf[i+1] <= 0x5f:
            insns.append((base+i, f"pop {REG64X[buf[i+1]-0x58]}")); i += 2
        elif b == 0x48 and i+1 < len(buf) and 0x90 <= buf[i+1] <= 0x97:
            insns.append((base+i, f"xchg rax, {REG64[buf[i+1]-0x90]}")); i += 2
        elif b == 0x48 and i+2 < len(buf) and buf[i+1] == 0x89:
            MOD = {0xe7:"mov rdi, rsp", 0xec:"mov rsp, rbp",
                   0xe5:"mov rbp, rsp", 0xd4:"mov rsp, rdx"}
            mn = MOD.get(buf[i+2])
            if mn:
                insns.append((base+i, mn)); i += 3
            else:
                break
        elif b == 0x48 and i+3 < len(buf) and buf[i+1] == 0x83 and buf[i+2] == 0xc4:
            insns.append((base+i, f"add rsp, 0x{buf[i+3]:x}")); i += 4
        elif b == 0x48 and i+3 < len(buf) and buf[i+1] == 0x83 and buf[i+2] == 0xec:
            insns.append((base+i, f"sub rsp, 0x{buf[i+3]:x}")); i += 4
        elif b == 0xcc:
            break
        else:
            break
    return insns

def disasm_seq(buf, base=0):
    if CS_AVAILABLE:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = False
        insns = []
        for insn in md.disasm(buf, base):
            insns.append((insn.address, f"{insn.mnemonic} {insn.op_str}".strip()))
            if insn.mnemonic == "ret":
                break
            if insn.mnemonic in ("jmp", "call", "int3"):
                break
        return insns
    return disasm_seq_fallback(buf, base)

def scan_gadgets(data):
    lines = ["\n[GADGETS]"]
    found = {}
    for end_off in range(1, len(data)):
        if data[end_off] not in (0xc3, 0xcb):
            continue
        for length in range(1, 9):
            start = end_off - length
            if start < 0:
                continue
            try:
                insns = disasm_seq(data[start:end_off+1], start)
                if len(insns) >= 2:
                    label = "; ".join(i[1] for i in insns)
                    if label not in found:
                        found[label] = start
            except Exception:
                pass
    for label, off in sorted(found.items(), key=lambda x: x[0]):
        lines.append(f"  [+] {label} @ 0x{off:x}")
    lines.append(f"  [{len(found)} unique gadgets]")
    lines.append("  [syscall sequences — first 20]")
    pos, count = 0, 0
    while count < 20:
        off = data.find(b'\x0f\x05', pos)
        if off == -1:
            break
        ctx = data[off:off+8].hex()
        try:
            insns = disasm_seq(data[max(0,off-6):off+3], off-6)
            label = "; ".join(i[1] for i in insns)
        except Exception:
            label = ""
        lines.append(f"      0x{off:x} -> {ctx}  [{label}]")
        pos = off + 1
        count += 1
    return lines

def scan_jop(data):
    lines = ["\n[JOP / COP GADGETS]"]
    jop_found = {}
    cop_found = {}
    vtable_found = []

    for pat, label in JOP_DISPATCHERS:
        for m in pat.finditer(data):
            off = m.start()
            ctx_start = max(0, off - 8)
            try:
                insns = disasm_seq(data[ctx_start:off + len(m.group())], ctx_start)
                full = "; ".join(i[1] for i in insns)
            except Exception:
                full = label
            key = f"{label} (ctx: {full})"
            if key not in jop_found:
                jop_found[key] = off

    for pat, label in COP_PATTERNS:
        for m in pat.finditer(data):
            off = m.start()
            ctx_start = max(0, off - 8)
            try:
                insns = disasm_seq(data[ctx_start:off + len(m.group())], ctx_start)
                full = "; ".join(i[1] for i in insns)
            except Exception:
                full = label
            key = f"{label} (ctx: {full})"
            if key not in cop_found:
                cop_found[key] = off

    for pat in VTABLE_PATTERNS:
        for m in pat.finditer(data):
            vtable_found.append(m.start())

    if jop_found:
        lines.append("  -- JOP dispatchers (indirect jmp/call via register) --")
        for label, off in list(jop_found.items())[:30]:
            lines.append(f"  [JOP] {label} @ 0x{off:x}")
    else:
        lines.append("  [-] no JOP dispatcher gadgets found")

    if cop_found:
        lines.append("  -- COP gadgets (indirect call through memory) --")
        for label, off in list(cop_found.items())[:20]:
            lines.append(f"  [COP] {label} @ 0x{off:x}")
    else:
        lines.append("  [-] no COP gadgets found")

    if vtable_found:
        lines.append(f"  -- vtable dispatch sequences: {len(vtable_found)} hits --")
        for off in vtable_found[:10]:
            lines.append(f"  [VT]  @ 0x{off:x}")
    else:
        lines.append("  [-] no vtable dispatch sequences found")

    lines.append(f"  [{len(jop_found)} JOP, {len(cop_found)} COP, {len(vtable_found)} vtable]")
    return lines

def scan_syscalls(data):
    lines = ["\n[SYSCALL WRAPPERS]"]
    seen = {}
    i = 0

    while i < len(data) - 12:
        num, advance = None, 0

        # Pattern 1: mov eax, imm32 (b8 xx xx xx xx)
        if data[i] == 0xb8:
            num = struct.unpack_from("<I", data, i+1)[0]; advance = 5

        # Pattern 2: mov rax, imm32 sign-extended (48 c7 c0 xx xx xx xx)
        elif data[i] == 0x48 and i+6 < len(data) and data[i+1] == 0xc7 and data[i+2] == 0xc0:
            num = struct.unpack_from("<I", data, i+3)[0]; advance = 7

        # Pattern 3: xor eax,eax / add eax,N pattern (smaller numbers)
        elif data[i] == 0x31 and i+3 < len(data) and data[i+1] == 0xc0 and data[i+2] == 0x83 and data[i+3] == 0xc0:
            num = data[i+4]; advance = 5

        # Pattern 4: PS5 BSD calling convention shim: mov r10, rcx then syscall
        if num is None and i+2 < len(data) and data[i:i+3] == b'\x49\x89\xca':
            rest = data[i+3:i+5]
            if rest == b'\x0f\x05':
                lines.append(f"  [shim] BSD conv adapter (mov r10,rcx; syscall) @ 0x{i:x}")
            i += 1
            continue

        if num is not None and num <= 0x2d2:
            rest = data[i+advance:i+advance+5]
            has_syscall = (
                rest[:2] == b'\x0f\x05' or
                rest[:3] == b'\x49\x89\xca' and rest[3:5] == b'\x0f\x05' or
                b'\x0f\x05' in rest
            )
            if has_syscall and num not in seen:
                seen[num] = i

        i += 1

    # Pattern 5: indirect dispatch table scan
    lines.append("  [extended patterns]")
    for pat in SYSCALL_DISPATCH_PATTERNS:
        for m in pat.finditer(data):
            off = m.start()
            lines.append(f"  [dispatch] @ 0x{off:x} -> {data[off:off+10].hex()}")
            if len(lines) > 200:
                break

    for num, off in sorted(seen.items()):
        name = SYSCALL_TABLE.get(num, "unknown")
        lines.append(f"  [+] 0x{num:03x} ({num:3d}) @ 0x{off:x}  {name}")
    lines.append(f"  [{len(seen)} syscall wrappers found]")
    return lines

def scan_kva_clusters(data, module_name):
    """
    Collect all KVA-range pointers and group by proximity to detect
    shared kernel object clusters across the dump.
    """
    lines = ["\n[KVA CLUSTER ANALYSIS]"]
    hits = []
    for i in range(0, len(data) - 8, 8):
        val = struct.unpack_from("<Q", data, i)[0]
        if 0xffff800000000000 <= val <= 0xfffffffffffffff0:
            hits.append((i, val))

    if not hits:
        lines.append("  [-] no KVA pointers found")
        return lines

    # Group into clusters within 0x100 bytes of each other
    clusters = []
    current = [hits[0]]
    for j in range(1, len(hits)):
        if hits[j][0] - hits[j-1][0] <= 0x100:
            current.append(hits[j])
        else:
            if len(current) >= 2:
                clusters.append(current)
            current = [hits[j]]
    if len(current) >= 2:
        clusters.append(current)

    lines.append(f"  {len(hits)} total KVA pointers, {len(clusters)} clusters")
    for cidx, cluster in enumerate(clusters[:10]):
        lines.append(f"  Cluster {cidx}: {len(cluster)} ptrs @ file offset 0x{cluster[0][0]:x}")
        base_kva = cluster[0][1]
        for off, kva in cluster:
            delta = kva - base_kva
            lines.append(f"    [0x{off:x}] KVA=0x{kva:016x}  delta_from_cluster_base=0x{delta:x} ({delta:+d})")

    # Look for the stable multi-module triplet pattern
    triplets = [c for c in clusters if len(c) >= 3]
    if triplets:
        lines.append(f"  [!] {len(triplets)} clusters with 3+ pointers — candidate shared kernel objects")

    return lines

def scan_ucred(data):
    lines = ["\n[UCRED / PROC HINTS]"]
    hits = []
    for i in range(0, len(data) - 16, 8):
        val = struct.unpack_from("<Q", data, i)[0]
        if 0xffff800000000000 <= val <= 0xfffffffffffffff0:
            uid = struct.unpack_from("<I", data, i+8)[0]
            if uid <= 0xffff:
                hits.append((i, val, uid))

    # Detect stride patterns in the list (struct size inference)
    if len(hits) >= 3:
        strides = [hits[k+1][0] - hits[k][0] for k in range(len(hits)-1)]
        from collections import Counter
        common = Counter(strides).most_common(3)
        lines.append(f"  Stride analysis (likely struct size): {common}")

    for off, kva, uid in hits[:20]:
        lines.append(f"  KVA 0x{kva:016x} @ 0x{off:x}  next_u32=0x{uid:x} ({uid})")
    if not hits:
        lines.append("  [-] no ucred-like patterns")
    for s in [b"p_ucred", b"cr_uid", b"cr_gid", b"cr_ruid", b"cr_svuid"]:
        off = data.find(s)
        if off != -1:
            lines.append(f"  [!] '{s.decode()}' @ 0x{off:x}")
    return lines

def scan_rsa_key_material(data):
    """
    Scan for RSA key material beyond the basic exponent marker:
    - DER SEQUENCE headers with plausible key lengths
    - Consecutive e=65537 occurrences (compiled-in key table)
    - PKCS#1 / PKCS#8 structure markers
    """
    lines = ["\n[RSA KEY MATERIAL DETAIL]"]

    # Find all DER SEQUENCE starts (0x30 0x82 = SEQUENCE, length > 255)
    der_hits = []
    pos = 0
    while True:
        off = data.find(b'\x30\x82', pos)
        if off == -1:
            break
        length = struct.unpack_from(">H", data, off+2)[0]
        der_hits.append((off, length))
        pos = off + 1

    lines.append(f"  DER SEQUENCE hits: {len(der_hits)}")
    for off, length in der_hits[:10]:
        tag_byte = data[off+4] if off+4 < len(data) else 0
        hint = {
            0x02: "INTEGER (likely key component)",
            0x30: "nested SEQUENCE (cert/key wrapper)",
            0x03: "BIT STRING (public key body)",
            0x04: "OCTET STRING (private key body)",
            0x06: "OID",
        }.get(tag_byte, f"tag=0x{tag_byte:02x}")
        lines.append(f"  @ 0x{off:x}  len={length}  inner={hint}")

    # Consecutive e=65537 clusters — compiled key table
    e_marker = b'\x00\x01\x00\x01'
    e_hits = []
    pos = 0
    while True:
        off = data.find(e_marker, pos)
        if off == -1:
            break
        e_hits.append(off)
        pos = off + 1

    if e_hits:
        # Group into clusters (within 0x20 bytes = likely same table)
        clusters, cur = [], [e_hits[0]]
        for j in range(1, len(e_hits)):
            if e_hits[j] - e_hits[j-1] <= 0x20:
                cur.append(e_hits[j])
            else:
                clusters.append(cur); cur = [e_hits[j]]
        clusters.append(cur)
        lines.append(f"  e=65537 occurrences: {len(e_hits)} in {len(clusters)} cluster(s)")
        for cidx, cluster in enumerate(clusters):
            span = cluster[-1] - cluster[0]
            lines.append(f"  Cluster {cidx}: {len(cluster)} entries, "
                         f"span=0x{span:x}, base=0x{cluster[0]:x}")
            if len(cluster) >= 3:
                lines.append(f"    [!] Compiled-in key parameter table — "
                             f"version-stable candidate for report")

    # PKCS#1 RSA private key OID: 1.2.840.113549.1.1.1
    pkcs1_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'
    pos = 0
    pkcs1_hits = []
    while True:
        off = data.find(pkcs1_oid, pos)
        if off == -1:
            break
        pkcs1_hits.append(off)
        pos = off + 1
    if pkcs1_hits:
        lines.append(f"  PKCS#1 RSA OID hits: {len(pkcs1_hits)}")
        for off in pkcs1_hits[:5]:
            lines.append(f"    @ 0x{off:x}")

    # EC key OID: 1.2.840.10045.2.1
    ec_oid = b'\x06\x07\x2a\x86\x48\xce\x3d\x02\x01'
    pos = 0
    ec_hits = []
    while True:
        off = data.find(ec_oid, pos)
        if off == -1:
            break
        ec_hits.append(off)
        pos = off + 1
    if ec_hits:
        lines.append(f"  EC key OID hits: {len(ec_hits)}")
        for off in ec_hits[:5]:
            lines.append(f"    @ 0x{off:x}")

    return lines

def scan_proc_advanced(data, libkernel_base):
    lines = ["\n[PROC / THREAD HEURISTIC HUNT (WITH STATIC OFFSETS)]"]

    # 1. Harvest all candidate ucred KVAs
    ucred_candidates = []
    for i in range(0, len(data) - 16, 8):
        val = struct.unpack_from("<Q", data, i)[0]
        if 0xffff800000000000 <= val <= 0xfffffffffffffff0:
            uid = struct.unpack_from("<I", data, i+8)[0]
            if uid <= 0xffff: # Plausible UID check
                ucred_candidates.append(val)

    if not ucred_candidates:
        lines.append("  [-] No ucred candidates found to cross-reference.")
        return lines

    ucred_candidates = set(ucred_candidates)
    lines.append(f"  [+] Harvested {len(ucred_candidates)} unique ucred KVAs. Cross-referencing...")

    # 2. Scan for POINTERS referencing these ucred KVAs
    proc_hits = {}
    for i in range(0, len(data) - 8, 8):
        val = struct.unpack_from("<Q", data, i)[0]
        if val in ucred_candidates:
            if val not in proc_hits:
                proc_hits[val] = []
            proc_hits[val].append(i)

    if not proc_hits:
        lines.append("  [-] No direct pointers to ucred candidates found in this module.")
    else:
        for ucred_kva, offsets in list(proc_hits.items())[:15]:

            # --- THE CALCULATION ---
            # Handle potential negative offsets cleanly just in case it mapped below the base
            if ucred_kva >= libkernel_base:
                offset_str = f"0x{(ucred_kva - libkernel_base):x}"
            else:
                offset_str = f"-0x{(libkernel_base - ucred_kva):x}"

            lines.append(f"  [!] ucred KVA: 0x{ucred_kva:016x} | STATIC OFFSET: {offset_str}")
            lines.append(f"      Referenced at {len(offsets)} locations (showing top 3):")

            # Limit the hex dumps to the first 3 hits so it doesn't blow up the console
            for off in offsets[:3]:
                start_peek = max(0, off - 16)
                end_peek = min(len(data), off + 24)
                hex_dump = data[start_peek:end_peek].hex()
                formatted_hex = " ".join(hex_dump[j:j+16] for j in range(0, len(hex_dump), 16))
                lines.append(f"      -> file offset 0x{off:x} | ctx: {formatted_hex}")

            if len(offsets) > 3:
                lines.append(f"      -> ... and {len(offsets) - 3} more locations.")

    return lines

def analyze_file(filepath, args):
    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        data = f.read()

    regions = parse_regions(data)
    lines   = []
    add     = lines.extend

    lines.append(f"\n{'='*60}")
    lines.append(f"MODULE: {filename}  ({len(data)/1024/1024:.2f} MB)")
    lines.append(f"{'='*60}")

    run_all = args.all or not any([
        args.regions, args.general, args.gadgets, args.jop,
        args.syscalls, args.dlsym, args.kernel, args.proc,
        args.strings, args.crypto, args.elfs, args.sqlite,
        args.ucred, args.split, args.kva_clusters, args.rsa_detail,
    ])

    if args.regions or run_all:
        lines.append("\n[REGION MAP]")
        for r in regions:
            lines.append(f"  {r['name']:<10} {hex(r['base'])} -> {hex(r['end'])}"
                         f"  prot={prot_str(r['prot']):<18} type=0x{r['type']:x}"
                         f"  {len(r['data'])//1024}KB")

    if args.split:
        lines.append(f"\n[SPLIT -> {args.split}]")
        add(split_regions(regions, args.split, filename))

    if args.general or run_all:
        lines.append(f"\n[GENERAL]")
        elf_magic = b'\x7fELF'
        lines.append(f"  ELF headers: {data.count(elf_magic)}")
        for sig, label in GENERAL_MARKERS.items():
            off = data.find(sig)
            if off != -1:
                lines.append(f"  [!] {label} @ 0x{off:x}")

    if args.gadgets or run_all:
        add(scan_gadgets(data))

    if args.jop or run_all:
        add(scan_jop(data))

    if args.syscalls or run_all:
        add(scan_syscalls(data))

    if args.dlsym or run_all:
        lines.append("\n[DLSYM WRAPPER]")
        sig = b'\x48\xc7\xc0\x4f\x02\x00\x00'
        off = data.find(sig)
        if off != -1:
            lines.append(f"  [+] @ 0x{off:x} next={data[off+7:off+10].hex()}")
        else:
            lines.append("  [-] not found")

    if args.kernel or run_all:
        lines.append("\n[KERNEL]")
        elf_off = data.find(b'\x7fELF')
        if elf_off != -1:
            lines.append(f"  ELF @ 0x{elf_off:x}")
            raw = data[elf_off+0x18:elf_off+0x20]
            if len(raw) == 8:
                lines.append(f"  Entry: {hex(struct.unpack('<Q', raw)[0])}")
        ptr_pattern = re.compile(b'.{5}\x80\xff\xff')
        for match in list(ptr_pattern.finditer(data))[-5:]:
            chunk = data[match.start():match.start()+8]
            if len(chunk) == 8:
                lines.append(f"  KVA: 0x{struct.unpack('<Q', chunk)[0]:016x} @ 0x{match.start():x}")

    if args.kva_clusters or run_all:
        add(scan_kva_clusters(data, filename))

    if args.proc or run_all:
        add(scan_proc_advanced(data, LIBKERNEL_BASE))

#    if args.proc or run_all:
#        lines.append("\n[PROC HUNT]")
#        off = data.find(PROC_SIGNATURE)
#        if off == -1:
#            lines.append("  [-] PROC_COMM not found")
#        else:
#            lines.append(f"  [+] PROC_COMM @ 0x{off:x}")
#            for i in range(off, max(0, off - 256), -8):
#                chunk = data[i:i+8]
#                if len(chunk) < 8:
#                    continue
#                val = struct.unpack("<Q", chunk)[0]
#                if 0xffff800000000000 <= val <= 0xfffffffffffffff0:
#                    rel = off - i
#                    lines.append(f"  [!!!] ucred={hex(val)} offset=-{hex(rel)}")
#                    break

    if args.ucred or run_all:
        add(scan_ucred(data))

    if args.strings or run_all:
        lines.append("\n[STRINGS]")
        all_strings = extract_strings(data)
        hits = [(o, s) for o, s in all_strings
                if any(kw in s.lower() for kw in STRING_KEYWORDS)]
        for off, s in hits:
            lines.append(f"  0x{off:x}: {s[:120]}")
        lines.append(f"  [{len(hits)} hits / {len(all_strings)} total]")

        utf16 = extract_strings_utf16(data)
        if utf16:
            lines.append("  [UTF-16 strings]")
            for off, s in utf16[:20]:
                lines.append(f"  0x{off:x} (UTF-16): {s[:120]}")

    if args.crypto or run_all:
        lines.append("\n[CRYPTO]")
        for sig, label in CRYPTO_MARKERS.items():
            hits, pos = [], 0
            while len(hits) < 5:
                off = data.find(sig, pos)
                if off == -1:
                    break
                hits.append(f"0x{off:x}"); pos = off + 1
            if hits:
                lines.append(f"  [+] {label}: {', '.join(hits)}")

    if args.rsa_detail or run_all:
        add(scan_rsa_key_material(data))

    if args.elfs or run_all:
        lines.append("\n[ELF HEADERS]")
        pos, type_map = 0, {1:"REL", 2:"EXEC", 3:"DYN", 4:"CORE"}
        while True:
            off = data.find(b'\x7fELF', pos)
            if off == -1:
                break
            chunk = data[off:off+0x40]
            if len(chunk) < 0x40:
                break
            e_type    = struct.unpack_from("<H", chunk, 0x10)[0]
            e_machine = struct.unpack_from("<H", chunk, 0x12)[0]
            e_entry   = struct.unpack_from("<Q", chunk, 0x18)[0]
            lines.append(f"  @ 0x{off:x} type={type_map.get(e_type, hex(e_type))}"
                         f" machine=0x{e_machine:x} entry=0x{e_entry:x}")
            pos = off + 4

    if args.sqlite or run_all:
        lines.append("\n[SQLITE]")
        sig, pos, found = b'SQLite format 3\x00', 0, False
        while True:
            off = data.find(sig, pos)
            if off == -1:
                break
            found = True
            page_size = struct.unpack_from(">H", data, off+16)[0]
            num_pages = struct.unpack_from(">I", data, off+28)[0]
            user_ver  = struct.unpack_from(">I", data, off+60)[0]
            lines.append(f"  @ 0x{off:x} page={page_size} pages={num_pages}"
                         f" ~{page_size*num_pages//1024}KB ver=0x{user_ver:x}")
            pos = off + 1
        if not found:
            lines.append("  [-] none found")

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="PS5 memory dump analysis tool")
    parser.add_argument("target",                              help="File or directory")
    parser.add_argument("--split",        metavar="DIR",      help="Split regions into files")
    parser.add_argument("--general",      action="store_true",help="General marker scan")
    parser.add_argument("--gadgets",      action="store_true",help="ROP gadget scan")
    parser.add_argument("--jop",          action="store_true",help="JOP/COP gadget scan")
    parser.add_argument("--syscalls",     action="store_true",help="Syscall wrapper detection")
    parser.add_argument("--dlsym",        action="store_true",help="dlsym wrapper scan")
    parser.add_argument("--kernel",       action="store_true",help="Kernel pointer/ELF analysis")
    parser.add_argument("--kva-clusters", action="store_true",help="KVA cluster/shared-object analysis",
                        dest="kva_clusters")
    parser.add_argument("--proc",         action="store_true",help="Hunt proc/ucred structure")
    parser.add_argument("--ucred",        action="store_true",help="ucred pattern scan")
    parser.add_argument("--regions",      action="store_true",help="Print region map")
    parser.add_argument("--strings",      action="store_true",help="Keyword string scan (ASCII + UTF-16)")
    parser.add_argument("--crypto",       action="store_true",help="Crypto/cert marker scan")
    parser.add_argument("--rsa-detail",   action="store_true",help="Detailed RSA/EC key material analysis",
                        dest="rsa_detail")
    parser.add_argument("--elfs",         action="store_true",help="ELF header scan")
    parser.add_argument("--sqlite",       action="store_true",help="SQLite database scan")
    parser.add_argument("--all",          action="store_true",help="Run all analyses")
    parser.add_argument("--out",          metavar="FILE",     help="Write output to file")
    parser.add_argument("--workers",      type=int, default=4,help="Parallel workers (default 4)")
    args = parser.parse_args()

    if not CS_AVAILABLE:
        print("[!] capstone not installed — falling back to basic disassembler")
        print("[!] pip install capstone for accurate gadget/JOP detection")

    if os.path.isdir(args.target):
        files = sorted(os.path.join(args.target, f)
                       for f in os.listdir(args.target) if f.endswith(".bin"))
    elif os.path.isfile(args.target):
        files = [args.target]
    else:
        print(f"[-] Not found: {args.target}"); return

    results = {}
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(analyze_file, f, args): f for f in files}
        for future in as_completed(futures):
            fp = futures[future]
            try:
                results[fp] = future.result()
            except Exception as e:
                results[fp] = f"\n[ERROR] {fp}: {e}"

    output = "\n".join(results[f] for f in files if f in results)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"[+] Written to {args.out}")
    else:
        print(output)

if __name__ == "__main__":
    main()
