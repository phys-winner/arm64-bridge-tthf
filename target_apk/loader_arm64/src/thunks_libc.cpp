// SPDX-License-Identifier: GPL-3.0-or-later
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_types.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <fnmatch.h>
#include <setjmp.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <wchar.h>
#include <android/log.h>
#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>
#include <unordered_map>
#include <map>
#include <string>
#include <sstream>
#include <thread>
#include <atomic>
#include <chrono>

#define LOG_TAG "GOF2_LibcThunks"
#include "bridge_logging.h"

static std::unordered_map<uint32_t, FILE*> g_file_map;
static uint32_t g_next_file_handle = 0x10001000;

static std::unordered_map<uint32_t, void*> g_tls_map;
static uint32_t g_next_tls_key = 1;

#undef st_atime
#undef st_mtime
#undef st_ctime
#undef st_atime_nsec
#undef st_mtime_nsec
#undef st_ctime_nsec

// 32-bit ARM Linux/Android struct stat layout
struct Arm32Stat {
    uint32_t st_dev;
    uint32_t st_ino;
    uint16_t st_mode;
    uint16_t st_nlink;
    uint16_t st_uid;
    uint16_t st_gid;
    uint32_t st_rdev;
    uint32_t st_size;
    uint32_t st_blksize;
    uint32_t st_blocks;
    uint32_t st_atime;
    uint32_t st_atime_nsec;
    uint32_t st_mtime;
    uint32_t st_mtime_nsec;
    uint32_t st_ctime;
    uint32_t st_ctime_nsec;
};

static void WriteArm32Stat(uint8_t* guest_base, uint32_t gaddr, const struct stat& st) {
    if (!gaddr) return;
    Arm32Stat* arm_st = reinterpret_cast<Arm32Stat*>(GuestToHost(guest_base, gaddr));
    if (!arm_st) return;
    memset(arm_st, 0, sizeof(Arm32Stat));
    arm_st->st_dev = static_cast<uint32_t>(st.st_dev);
    arm_st->st_ino = static_cast<uint32_t>(st.st_ino);
    arm_st->st_mode = static_cast<uint16_t>(st.st_mode);
    arm_st->st_nlink = static_cast<uint16_t>(st.st_nlink);
    arm_st->st_uid = static_cast<uint16_t>(st.st_uid);
    arm_st->st_gid = static_cast<uint16_t>(st.st_gid);
    arm_st->st_rdev = static_cast<uint32_t>(st.st_rdev);
    arm_st->st_size = static_cast<uint32_t>(st.st_size);
    arm_st->st_blksize = static_cast<uint32_t>(st.st_blksize);
    arm_st->st_blocks = static_cast<uint32_t>(st.st_blocks);
    arm_st->st_atime = static_cast<uint32_t>(st.st_atim.tv_sec);
    arm_st->st_mtime = static_cast<uint32_t>(st.st_mtim.tv_sec);
    arm_st->st_ctime = static_cast<uint32_t>(st.st_ctim.tv_sec);
}

// Guest printf formatter
static std::string FormatGuestString(Dynarmic::A32::Jit& jit, DynarmicHost& host, const char* fmt, int first_arg_reg) {
    if (!fmt) return "";
    std::string result;
    int reg_idx = first_arg_reg;
    uint32_t sp = jit.Regs()[13];
    int stack_offset = 0;

    auto get_next_arg = [&]() -> uint32_t {
        if (reg_idx <= 3) {
            return jit.Regs()[reg_idx++];
        } else {
            uint32_t val = host.MemoryRead32(sp + stack_offset);
            stack_offset += 4;
            return val;
        }
    };

    const char* p = fmt;
    while (*p) {
        if (*p == '%' && *(p + 1)) {
            p++;
            if (*p == '%') {
                result += '%';
                p++;
                continue;
            }
            // Skip width/modifiers
            while (*p && (*p == '-' || *p == '+' || *p == ' ' || *p == '#' || *p == '0' ||
                          isdigit(*p) || *p == '.' || *p == 'l' || *p == 'h' || *p == 'z')) {
                p++;
            }
            if (*p == 's') {
                uint32_t gstr = get_next_arg();
                const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), gstr));
                result += (str ? str : "(null)");
            } else if (*p == 'd' || *p == 'i') {
                int32_t val = static_cast<int32_t>(get_next_arg());
                result += std::to_string(val);
            } else if (*p == 'u') {
                uint32_t val = get_next_arg();
                result += std::to_string(val);
            } else if (*p == 'x' || *p == 'X' || *p == 'p') {
                uint32_t val = get_next_arg();
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%X", val);
                result += buf;
            } else if (*p == 'f' || *p == 'g') {
                uint32_t val = get_next_arg();
                float f = *reinterpret_cast<float*>(&val);
                char buf[32];
                snprintf(buf, sizeof(buf), "%f", f);
                result += buf;
            } else if (*p == 'c') {
                char c = static_cast<char>(get_next_arg());
                result += c;
            } else {
                result += *p;
            }
            if (*p) p++;
        } else {
            result += *p++;
        }
    }
    return result;
}

// libfmodex probes /proc/cpuinfo for "vfp"/"vfpv3"/"neon" and disables its
// ARM SIMD paths (and then fails System::init) when it cannot find them. The
// host is aarch64, so the real file advertises "asimd" instead and the parser
// comes up empty. Hand it a synthetic ARMv7 cpuinfo over a pipe — the JIT does
// implement VFPv3+NEON for the guest, so this is accurate for the guest's view.
static int OpenSyntheticCpuInfo() {
    static const char kCpuInfo[] =
        "Processor\t: ARMv7 Processor rev 4 (v7l)\n"
        "processor\t: 0\n"
        "BogoMIPS\t: 38.40\n"
        "Features\t: swp half thumb fastmult vfp edsp neon vfpv3 vfpv3d16 tls vfpv4 idiva idivt\n"
        "CPU implementer\t: 0x41\n"
        "CPU architecture: 7\n"
        "CPU variant\t: 0x0\n"
        "CPU part\t: 0xd03\n"
        "CPU revision\t: 4\n"
        "\n"
        "Hardware\t: Generic ARMv7\n"
        "Revision\t: 0000\n"
        "Serial\t\t: 0000000000000000\n";
    int fds[2];
    if (pipe(fds) != 0) return -1;
    (void)!write(fds[1], kCpuInfo, sizeof(kCpuInfo) - 1);
    close(fds[1]);
    return fds[0];
}

// A pthread object living in the first guest page means the guest dereferenced
// a null pointer to get there (Scaleform's queue walks an uninitialised waiter
// list that way when the GL thread runs ahead of the player constructor). On a
// real device that store/lock would segfault; here it used to wedge the GL
// thread on a phantom mutex and stall the whole boot. Treat it as a no-op.
static bool IsNullGuestSyncObject(uint32_t addr) {
    if (addr >= 0x1000) return false;
    static std::atomic<int> n{0};
    if (n.fetch_add(1) < 10)
        TT_ANDROID_LOG_PRINT(ANDROID_LOG_ERROR, LOG_TAG,
                            "[SYNC] ignoring pthread op on null object 0x%08X", addr);
    return true;
}

// Bulk memory ops with a length the guest computed from corrupted state used
// to touch gigabytes of the arena; cap them at something no real allocation in
// this game reaches and make sure the whole range stays inside guest memory.
static bool GuestRangeOk(DynarmicHost& host, uint32_t addr, size_t n, const char* what) {
    static constexpr size_t kMaxBulk = 64u * 1024 * 1024;
    if (n <= kMaxBulk && static_cast<uint64_t>(addr) + n <= host.GetGuestMemorySize()) return true;
    static std::atomic<int> c{0};
    if (c.fetch_add(1) < 10)
        TT_ANDROID_LOG_PRINT(ANDROID_LOG_ERROR, LOG_TAG,
                            "[MEM] %s: refusing 0x%08X + %zu bytes", what, addr, n);
    return false;
}

void ThunkManager::RegisterLibcThunks() {
    uint8_t* mem = m_host.GetGuestMemoryBase();

    *reinterpret_cast<uint32_t*>(mem + 0x100) = 0xDEADBEEF;
    *reinterpret_cast<uint32_t*>(mem + 0x300) = 0;

    m_symbol_to_address["__stack_chk_guard"] = 0x100;
    m_symbol_to_address["__sF"] = 0x200;

    RegisterThunk("__errno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0x300;
    });

    // -------------------------------------------------------------
    // Additional POSIX & Math Thunks for FMOD
    // -------------------------------------------------------------

    auto read_double_01 = [](const Dynarmic::A32::Jit& jit) -> double {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        return val;
    };
    auto write_double_01 = [](Dynarmic::A32::Jit& jit, double val) {
        uint64_t raw;
        memcpy(&raw, &val, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((raw >> 32) & 0xFFFFFFFF);
    };

    RegisterThunk("sin", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sin(read_double_01(jit)));
    });
    RegisterThunk("cos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, cos(read_double_01(jit)));
    });
    RegisterThunk("tan", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, tan(read_double_01(jit)));
    });
    RegisterThunk("acos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, acos(read_double_01(jit)));
    });
    RegisterThunk("atan2", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double y = read_double_01(jit);
        uint64_t raw_x = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double x;
        memcpy(&x, &raw_x, sizeof(double));
        write_double_01(jit, atan2(y, x));
    });
    RegisterThunk("exp", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, exp(read_double_01(jit)));
    });
    RegisterThunk("log", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log(read_double_01(jit)));
    });
    RegisterThunk("log10", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log10(read_double_01(jit)));
    });
    RegisterThunk("log10f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = ReadSF(jit, 0);
        WriteSF(jit, 0, log10f(val));
    });
    RegisterThunk("pow", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double x = read_double_01(jit);
        uint64_t raw_y = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double y;
        memcpy(&y, &raw_y, sizeof(double));
        write_double_01(jit, pow(x, y));
    });
    RegisterThunk("sqrt", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sqrt(read_double_01(jit)));
    });
    RegisterThunk("floor", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, floor(read_double_01(jit)));
    });
    RegisterThunk("rint", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, rint(read_double_01(jit)));
    });
    RegisterThunk("lrintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = ReadSF(jit, 0);
        jit.Regs()[0] = static_cast<uint32_t>(lrintf(val));
    });
    RegisterThunk("frexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double val = ReadDF(jit, 0);
        uint32_t exp_ptr = jit.Regs()[2]; // softfp: double in r0:r1, int* in r2
        int exp_val = 0;
        double res = frexp(val, &exp_val);
        if (exp_ptr) host.MemoryWrite32(exp_ptr, static_cast<uint32_t>(exp_val));
        WriteDF(jit, 0, res);
    });
    RegisterThunk("ldexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double val = ReadDF(jit, 0);
        int exp_val = static_cast<int>(jit.Regs()[2]); // softfp: double in r0:r1, int in r2
        WriteDF(jit, 0, ldexp(val, exp_val));
    });

    // Memory & Strings
    RegisterThunk("memmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        void* h_dst = GuestToHost(host.GetGuestMemoryBase(), dst);
        const void* h_src = GuestToHost(host.GetGuestMemoryBase(), src);
        if (h_dst && h_src && n > 0) memmove(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("memmem", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t haystack = jit.Regs()[0];
        uint32_t hlen = jit.Regs()[1];
        uint32_t needle = jit.Regs()[2];
        uint32_t nlen = jit.Regs()[3];
        const void* h_hay = GuestToHost(host.GetGuestMemoryBase(), haystack);
        const void* h_nee = GuestToHost(host.GetGuestMemoryBase(), needle);
        if (h_hay && h_nee && hlen >= nlen) {
            const void* found = memmem(h_hay, hlen, h_nee, nlen);
            if (found) {
                uint32_t offset = static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(found) - reinterpret_cast<const uint8_t*>(h_hay));
                jit.Regs()[0] = haystack + offset;
                return;
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("strcat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src) strcat(h_dst, h_src);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strncpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src && n > 0) strncpy(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strncasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s1 = jit.Regs()[0];
        uint32_t s2 = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        const char* h_s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s1));
        const char* h_s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s2));
        jit.Regs()[0] = (h_s1 && h_s2) ? static_cast<uint32_t>(strncasecmp(h_s1, h_s2, n)) : 0;
    });
    RegisterThunk("strtol", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t nptr = jit.Regs()[0];
        uint32_t endptr = jit.Regs()[1];
        int base = static_cast<int>(jit.Regs()[2]);
        const char* h_nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), nptr));
        if (!h_nptr) { jit.Regs()[0] = 0; return; }
        char* h_end = nullptr;
        long val = strtol(h_nptr, &h_end, base);
        if (endptr && h_end) {
            uint32_t offset = static_cast<uint32_t>(h_end - h_nptr);
            host.MemoryWrite32(endptr, nptr + offset);
        }
        jit.Regs()[0] = static_cast<uint32_t>(val);
    });
    RegisterThunk("puts", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s = jit.Regs()[0];
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s));
        if (str) LOGI("[puts] %s", str);
        jit.Regs()[0] = 1;
    });
    RegisterThunk("vsnprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t buf = jit.Regs()[0];
        uint32_t size = jit.Regs()[1];
        uint32_t fmt = jit.Regs()[2];
        char* h_buf = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), buf));
        const char* h_fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), fmt));
        if (!h_buf || size == 0) { jit.Regs()[0] = 0; return; }
        if (!h_fmt) { h_buf[0] = 0; jit.Regs()[0] = 0; return; }
        strncpy(h_buf, h_fmt, size - 1);
        h_buf[size - 1] = 0;
        jit.Regs()[0] = static_cast<uint32_t>(strlen(h_buf));
    });

    // Time & Threading
    RegisterThunk("gettimeofday", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t tv_ptr = jit.Regs()[0];
        if (tv_ptr) {
            struct timeval tv;
            gettimeofday(&tv, nullptr);
            host.MemoryWrite32(tv_ptr + 0, static_cast<uint32_t>(tv.tv_sec));
            host.MemoryWrite32(tv_ptr + 4, static_cast<uint32_t>(tv.tv_usec));
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("lrand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(lrand48());
    });
    RegisterThunk("srand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        srand48(static_cast<long>(jit.Regs()[0]));
        jit.Regs()[0] = 0;
    });
    RegisterThunk("utime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("unlink", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("chown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("fcntl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        int cmd = static_cast<int>(jit.Regs()[1]);
        int arg = static_cast<int>(jit.Regs()[2]);
        int res = (fd >= 0) ? fcntl(fd, cmd, arg) : 0;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    // Sockets & Net
    RegisterThunk("socket", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int domain = static_cast<int>(jit.Regs()[0]);
        int type = static_cast<int>(jit.Regs()[1]);
        int protocol = static_cast<int>(jit.Regs()[2]);
        int fd = socket(domain, type, protocol);
        jit.Regs()[0] = static_cast<uint32_t>(fd);
    });

    RegisterThunk("bind", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t addr_ptr = jit.Regs()[1];
        socklen_t len = static_cast<socklen_t>(jit.Regs()[2]);
        const struct sockaddr* addr = reinterpret_cast<const struct sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), addr_ptr));
        int res = (addr && fd >= 0) ? bind(fd, addr, len) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("listen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        int backlog = static_cast<int>(jit.Regs()[1]);
        int res = (fd >= 0) ? listen(fd, backlog) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("accept", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t addr_ptr = jit.Regs()[1];
        uint32_t len_ptr = jit.Regs()[2];
        struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), addr_ptr));
        socklen_t* plen = reinterpret_cast<socklen_t*>(GuestToHost(host.GetGuestMemoryBase(), len_ptr));
        int res = (fd >= 0) ? accept(fd, addr, plen) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("connect", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t addr_ptr = jit.Regs()[1];
        socklen_t len = static_cast<socklen_t>(jit.Regs()[2]);
        const struct sockaddr* addr = reinterpret_cast<const struct sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), addr_ptr));
        int res = (addr && fd >= 0) ? connect(fd, addr, len) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("send", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t buf_ptr = jit.Regs()[1];
        size_t len = jit.Regs()[2];
        int flags = static_cast<int>(jit.Regs()[3]);
        const void* buf = GuestToHost(host.GetGuestMemoryBase(), buf_ptr);
        ssize_t res = (buf && fd >= 0) ? send(fd, buf, len, flags) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("recv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t buf_ptr = jit.Regs()[1];
        size_t len = jit.Regs()[2];
        int flags = static_cast<int>(jit.Regs()[3]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), buf_ptr);
        ssize_t res = (buf && fd >= 0) ? recv(fd, buf, len, flags) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("setsockopt", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        int level = static_cast<int>(jit.Regs()[1]);
        int optname = static_cast<int>(jit.Regs()[2]);
        uint32_t optval_ptr = jit.Regs()[3];
        socklen_t optlen = static_cast<socklen_t>(host.MemoryRead32(jit.Regs()[13]));
        const void* optval = GuestToHost(host.GetGuestMemoryBase(), optval_ptr);
        int res = (optval && fd >= 0) ? setsockopt(fd, level, optname, optval, optlen) : 0;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("getsockname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t addr_ptr = jit.Regs()[1];
        uint32_t len_ptr = jit.Regs()[2];
        struct sockaddr* addr = reinterpret_cast<struct sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), addr_ptr));
        socklen_t* plen = reinterpret_cast<socklen_t*>(GuestToHost(host.GetGuestMemoryBase(), len_ptr));
        int res = (fd >= 0 && addr && plen) ? getsockname(fd, addr, plen) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("select", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("inet_addr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t cp_ptr = jit.Regs()[0];
        const char* cp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), cp_ptr));
        in_addr_t addr = cp ? inet_addr(cp) : INADDR_NONE;
        jit.Regs()[0] = static_cast<uint32_t>(addr);
    });
    RegisterThunk("gethostbyname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Android & Runtime
    RegisterThunk("__android_log_write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
#if !defined(TT_RELEASE_NO_LOGS)
        int prio = static_cast<int>(jit.Regs()[0]);
        uint32_t tag_ptr = jit.Regs()[1];
        uint32_t msg_ptr = jit.Regs()[2];
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), tag_ptr));
        const char* msg = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), msg_ptr));
        if (tag && msg) TT_ANDROID_LOG_WRITE(prio, tag, msg);
#endif
        jit.Regs()[0] = 1;
    });
    RegisterThunk("__aeabi_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_pure_virtual", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("__cxa_pure_virtual called!");
        jit.Regs()[0] = 0;
    });
    RegisterThunk("__cxa_type_match", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_begin_cleanup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_call_unexpected", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__system_property_get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        char* val = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (val) {
            if (name && strcmp(name, "ro.build.version.sdk") == 0) {
                strcpy(val, "26");
                jit.Regs()[0] = 2;
                return;
            }
            strcpy(val, "1");
            jit.Regs()[0] = 1;
            return;
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("dlopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t name_ptr = jit.Regs()[0];
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), name_ptr));
        jit.Regs()[0] = 0x50005000; // Non-null handle
    });
    RegisterThunk("dlclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlsym", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sym_ptr = jit.Regs()[1];
        const char* sym = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), sym_ptr));
        if (sym) {
            static std::map<std::string, uint32_t> s_iid_ptrs;
            auto get_or_create_iid = [&](const std::string& name, const SLInterfaceID id) -> uint32_t {
                auto it = s_iid_ptrs.find(name);
                if (it != s_iid_ptrs.end()) return it->second;
                uint32_t struct_addr = host.GuestAlloc(sizeof(struct SLInterfaceID_), 16);
                memcpy(GuestToHost(host.GetGuestMemoryBase(), struct_addr), id, sizeof(struct SLInterfaceID_));

                uint32_t ptr_addr = host.GuestAlloc(4, 4);
                *reinterpret_cast<uint32_t*>(GuestToHost(host.GetGuestMemoryBase(), ptr_addr)) = struct_addr;
                s_iid_ptrs[name] = ptr_addr;
                LOGI("dlsym: Created OpenSL ES IID '%s' -> ptr=0x%08X (*ptr=0x%08X)", name.c_str(), ptr_addr, struct_addr);
                return ptr_addr;
            };

            if (strcmp(sym, "SL_IID_ENGINE") == 0) {
                jit.Regs()[0] = get_or_create_iid(sym, SL_IID_ENGINE);
                return;
            }
            if (strcmp(sym, "SL_IID_PLAY") == 0) {
                jit.Regs()[0] = get_or_create_iid(sym, SL_IID_PLAY);
                return;
            }
            if (strcmp(sym, "SL_IID_ANDROIDSIMPLEBUFFERQUEUE") == 0) {
                jit.Regs()[0] = get_or_create_iid(sym, SL_IID_ANDROIDSIMPLEBUFFERQUEUE);
                return;
            }
            if (strcmp(sym, "SL_IID_BUFFERQUEUE") == 0) {
                jit.Regs()[0] = get_or_create_iid(sym, SL_IID_BUFFERQUEUE);
                return;
            }
            if (strcmp(sym, "SL_IID_VOLUME") == 0) {
                jit.Regs()[0] = get_or_create_iid(sym, SL_IID_VOLUME);
                return;
            }
            if (strcmp(sym, "SL_IID_OUTPUTMIX") == 0) {
                jit.Regs()[0] = get_or_create_iid(sym, SL_IID_OUTPUTMIX);
                return;
            }

            uint32_t addr = host.GetThunkManager().GetOrCreateThunkAddress(sym);
            jit.Regs()[0] = addr;
            return;
        }
        jit.Regs()[0] = 0;
    });

    // C++ Memory Allocation operators
    RegisterThunk("_Znaj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_Znwj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnajRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnwjRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZdaPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZdlPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZNSt8ios_base4InitC1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_ZNSt8ios_base4InitD1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});

    // Memory Allocation inside guest space
    RegisterThunk("malloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("calloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t num = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        uint32_t addr = host.GuestAlloc(num * size, 8);
        if (addr) {
            memset(GuestToHost(host.GetGuestMemoryBase(), addr), 0, num * size);
        }
        jit.Regs()[0] = addr;
    });

    RegisterThunk("realloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t old_addr = jit.Regs()[0];
        size_t new_size = jit.Regs()[1];
        uint32_t new_addr = host.GuestAlloc(new_size, 8);
        if (old_addr && new_addr) {
            // Blocks carry their payload size now, so stop copying new_size bytes
            // out of a block that may be smaller than that.
            uint32_t old_size = host.GuestAllocSize(old_addr);
            size_t copy = (old_size && old_size < new_size) ? old_size : new_size;
            memcpy(GuestToHost(host.GetGuestMemoryBase(), new_addr),
                   GuestToHost(host.GetGuestMemoryBase(), old_addr), copy);
            host.GuestFree(old_addr);
        }
        jit.Regs()[0] = new_addr;
    });

    RegisterThunk("free", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("memalign", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t alignment = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        jit.Regs()[0] = host.GuestAlloc(size, alignment);
    });

    // Logging & Formatted output
    RegisterThunk("__android_log_print", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
#if !defined(TT_RELEASE_NO_LOGS)
        int prio = static_cast<int>(jit.Regs()[0]);
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        std::string formatted = FormatGuestString(jit, host, fmt, 3);
        TT_ANDROID_LOG_PRINT(prio, tag ? tag : "GOF2_Guest", "[GUEST] %s", formatted.c_str());
#endif
        jit.Regs()[0] = 0;
    });

    RegisterThunk("printf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        std::string formatted = FormatGuestString(jit, host, fmt, 1);
        LOGI("[printf] %s", formatted.c_str());
        jit.Regs()[0] = formatted.length();
    });

    RegisterThunk("fprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        std::string formatted = FormatGuestString(jit, host, fmt, 2);
        LOGI("[fprintf] %s", formatted.c_str());
        jit.Regs()[0] = formatted.length();
    });

    RegisterThunk("sprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* str = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        std::string formatted = FormatGuestString(jit, host, fmt, 2);
        if (str) {
            strcpy(str, formatted.c_str());
            jit.Regs()[0] = formatted.length();
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("snprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* str = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t size = jit.Regs()[1];
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        std::string formatted = FormatGuestString(jit, host, fmt, 3);
        if (str && size > 0) {
            strncpy(str, formatted.c_str(), size - 1);
            str[size - 1] = '\0';
            jit.Regs()[0] = formatted.length();
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("sscanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("vfprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("vasprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("putc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });
    RegisterThunk("fputc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });

    // Math functions (hard-float: args in s0/s1, result in s0)
    RegisterThunk("sinf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, sinf(ReadSF(jit, 0))); });
    RegisterThunk("cosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, cosf(ReadSF(jit, 0))); });
    RegisterThunk("sqrtf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, sqrtf(ReadSF(jit, 0))); });
    RegisterThunk("atanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, atanf(ReadSF(jit, 0))); });
    RegisterThunk("acosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, acosf(ReadSF(jit, 0))); });
    RegisterThunk("asinf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, asinf(ReadSF(jit, 0))); });
    RegisterThunk("tanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, tanf(ReadSF(jit, 0))); });
    RegisterThunk("ceilf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, ceilf(ReadSF(jit, 0))); });
    RegisterThunk("floorf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, floorf(ReadSF(jit, 0))); });
    RegisterThunk("logf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { WriteSF(jit, 0, logf(ReadSF(jit, 0))); });
    RegisterThunk("atan2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        WriteSF(jit, 0, atan2f(ReadSF(jit, 0), ReadSF(jit, 1)));
    });
    RegisterThunk("fmodf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        WriteSF(jit, 0, fmodf(ReadSF(jit, 0), ReadSF(jit, 1)));
    });
    RegisterThunk("modff", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float x = ReadSF(jit, 0);
        uint32_t iptr = jit.Regs()[0];
        float ipart = 0.0f;
        float res = modff(x, &ipart);
        if (iptr) host.MemoryWrite32(iptr, *reinterpret_cast<uint32_t*>(&ipart));
        WriteSF(jit, 0, res);
    });
    RegisterThunk("powf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        WriteSF(jit, 0, powf(ReadSF(jit, 0), ReadSF(jit, 1)));
    });
    // double variants (hard-float: args in d0/d1, result in d0)
    RegisterThunk("asin", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) { write_double_01(jit, asin(read_double_01(jit))); });
    RegisterThunk("atan", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) { write_double_01(jit, atan(read_double_01(jit))); });
    RegisterThunk("ceil", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) { write_double_01(jit, ceil(read_double_01(jit))); });
    RegisterThunk("fmod", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double x = read_double_01(jit);
        uint64_t raw_y = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double y;
        memcpy(&y, &raw_y, sizeof(double));
        write_double_01(jit, fmod(x, y));
    });
    RegisterThunk("modf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double x = ReadDF(jit, 0);
        uint32_t iptr = jit.Regs()[0];
        double ipart = 0;
        double res = modf(x, &ipart);
        if (iptr) host.MemoryWrite64(iptr, *reinterpret_cast<uint64_t*>(&ipart));
        WriteDF(jit, 0, res);
    });

    // String & Memory functions
    RegisterThunk("strcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcmp(s1, s2) : 0;
    });

    RegisterThunk("strncmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? strncmp(s1, s2, n) : 0;
    });

    RegisterThunk("strcasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcasecmp(s1, s2) : 0;
    });

    RegisterThunk("strlen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = s ? static_cast<uint32_t>(strlen(s)) : 0;
    });

    RegisterThunk("strcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (dest && src) strcpy(dest, src);
    });

    RegisterThunk("strdup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!src) { jit.Regs()[0] = 0; return; }
        size_t len = strlen(src) + 1;
        uint32_t dest_addr = host.GuestAlloc(len);
        memcpy(GuestToHost(host.GetGuestMemoryBase(), dest_addr), src, len);
        jit.Regs()[0] = dest_addr;
    });

    RegisterThunk("strrchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int c = static_cast<int>(jit.Regs()[1]);
        if (!s) { jit.Regs()[0] = 0; return; }
        const char* res = strrchr(s, c);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });

    RegisterThunk("strerror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* err = strerror(static_cast<int>(jit.Regs()[0]));
        size_t len = strlen(err) + 1;
        uint32_t dest = host.GuestAlloc(len);
        memcpy(GuestToHost(host.GetGuestMemoryBase(), dest), err, len);
        jit.Regs()[0] = dest;
    });

    RegisterThunk("strtoul", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int base = static_cast<int>(jit.Regs()[2]);
        jit.Regs()[0] = nptr ? static_cast<uint32_t>(strtoul(nptr, nullptr, base)) : 0;
    });

    RegisterThunk("atoi", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = str ? atoi(str) : 0;
    });

    RegisterThunk("islower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = islower(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("isxdigit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = isxdigit(static_cast<int>(jit.Regs()[0]));
    });

    // NOTE: these replace the earlier registrations of the same names, so the
    // length guard has to live here too. A garbage length (which happens when
    // the guest's own allocator state gets corrupted) would otherwise fault in
    // gigabytes of the 4 GB arena and get the process LMK-killed.
    RegisterThunk("memset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t g_s = jit.Regs()[0];
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        void* s = GuestToHost(host.GetGuestMemoryBase(), g_s);
        if (!s || n == 0) { jit.Regs()[0] = g_s; return; }
        if (!GuestRangeOk(host, g_s, n, "memset")) { jit.Regs()[0] = g_s; return; }
        memset(s, c, n);
        jit.Regs()[0] = g_s;
    });

    RegisterThunk("memcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t g_dst = jit.Regs()[0], g_src = jit.Regs()[1];
        size_t n = jit.Regs()[2];
        void* dest = GuestToHost(host.GetGuestMemoryBase(), g_dst);
        const void* src = GuestToHost(host.GetGuestMemoryBase(), g_src);
        if (!dest || !src || n == 0) { jit.Regs()[0] = g_dst; return; }
        if (!GuestRangeOk(host, g_dst, n, "memcpy") || !GuestRangeOk(host, g_src, n, "memcpy")) {
            jit.Regs()[0] = g_dst; return;
        }
        memmove(dest, src, n);
        jit.Regs()[0] = g_dst;
    });

    RegisterThunk("memcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s1 = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s2 = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? memcmp(s1, s2, n) : 0;
    });

    RegisterThunk("memchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        void* res = s ? const_cast<void*>(memchr(s, c, n)) : nullptr;
        jit.Regs()[0] = res ? HostToGuest(host.GetGuestMemoryBase(), res) : 0;
    });

    RegisterThunk("qsort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});

    // ARM AEABI Helpers
    RegisterThunk("__aeabi_idiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_uidiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_idivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uidivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uldivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t num = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        uint64_t den = static_cast<uint64_t>(jit.Regs()[2]) | (static_cast<uint64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            uint64_t q = num / den;
            uint64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__gnu_ldivmod_helper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t num = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        int64_t den = static_cast<int64_t>(jit.Regs()[2]) | (static_cast<int64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            int64_t q = num / den;
            int64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    // AEABI memory functions
    auto aeabi_memclr_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), 0, n);
        }
    };
    RegisterThunk("__aeabi_memclr", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr4", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr8", aeabi_memclr_handler);

    auto aeabi_memset_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        int c = static_cast<int>(jit.Regs()[2]);
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), c, n);
        }
    };
    RegisterThunk("__aeabi_memset", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset4", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset8", aeabi_memset_handler);

    auto aeabi_memcpy_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        if (dest && src && n && n <= 0x20000000) {
            memmove(GuestToHost(host.GetGuestMemoryBase(), dest),
                    GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memcpy", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy4", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy8", aeabi_memcpy_handler);

    auto aeabi_memmove_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        if (dest && src && n) {
            memmove(GuestToHost(host.GetGuestMemoryBase(), dest),
                    GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memmove", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove4", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove8", aeabi_memmove_handler);

    RegisterThunk("pthread_attr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_attr_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_attr_setstacksize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_attr_setschedparam", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_attr_setschedpolicy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_attr_setdetachstate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    RegisterThunk("pthread_self", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> s_self_tid{200};
        thread_local uint32_t t_tid = s_self_tid.fetch_add(1);
        jit.Regs()[0] = t_tid;
    });

    RegisterThunk("pthread_equal", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = (jit.Regs()[0] == jit.Regs()[1]) ? 1 : 0;
    });

    RegisterThunk("pthread_detach", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_join", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    RegisterThunk("sched_get_priority_min", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 1; });
    RegisterThunk("sched_get_priority_max", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 99; });
    RegisterThunk("sched_setscheduler", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("sched_yield", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::this_thread::yield();
        jit.Regs()[0] = 0;
    });

    RegisterThunk("usleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t usec = jit.Regs()[0];
        std::this_thread::sleep_for(std::chrono::microseconds(usec));
        jit.Regs()[0] = 0;
    });

    RegisterThunk("nanosleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t req_ptr = jit.Regs()[0];
        if (req_ptr) {
            uint32_t sec = host.MemoryRead32(req_ptr);
            uint32_t nsec = host.MemoryRead32(req_ptr + 4);
            std::this_thread::sleep_for(std::chrono::seconds(sec) + std::chrono::nanoseconds(nsec));
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("sleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sec = jit.Regs()[0];
        std::this_thread::sleep_for(std::chrono::seconds(sec));
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t thread_ptr = jit.Regs()[0];
        uint32_t start_routine = jit.Regs()[2];
        uint32_t arg = jit.Regs()[3];

        static std::atomic<uint32_t> s_next_tid{100};
        uint32_t tid = s_next_tid++;
        if (thread_ptr) host.MemoryWrite32(thread_ptr, tid);
        if (!start_routine) {
            jit.Regs()[0] = 22; // EINVAL
            return;
        }
        // Each guest thread gets its own Jit instance + guest stack. The host
        // object outlives all threads (app lifetime).
        std::thread([&host, start_routine, arg]() {
            std::unique_ptr<Dynarmic::A32::Jit> thread_jit = host.CreateJitInstance();
            uint32_t stack_top = host.AllocGuestStack();
            // Scaleform's one-shot worker pops a single task per invocation;
            // the real manager re-spawns workers until the queue drains.
            // Re-run the routine so leftover (nested) tasks also complete.
            for (int i = 0; i < 64; ++i) {
                host.RunFunctionOnJit(*thread_jit, stack_top, start_routine, {arg});
                uint32_t drain_check = host.MemoryRead32(0x500011A8);
                if (drain_check == 0 || drain_check >= 0x10000) break;
            }
        }).detach();
        jit.Regs()[0] = 0;
    });

    // Pthreads & Threading: tolerant emulation. The game uses Scaleform's own
    // sync wrapper protocol (locks a wrapper pointer, unlocks an inner
    // pointer; cond_wait may receive an unlocked mutex). Host-side blocking
    // is keyed per guest address; unlock of an unowned key is a no-op, and
    // cond waits use the cond's own internal mutex (never the guest mutex).
    static std::mutex g_pt_mutex;
    struct MutexObj {
        std::recursive_mutex mtx;
        std::atomic<int64_t> owner{0}; // host tid while held (0 = free)
        std::atomic<int> locked{0};    // recursive hold count of owner
    };
    static std::unordered_map<uint32_t, std::unique_ptr<MutexObj>> g_guest_mutexes;
    struct CondObj {
        std::mutex wait_mtx;
        std::condition_variable cv;
        std::atomic<int> sticky{0};
    };
    static std::unordered_map<uint32_t, std::unique_ptr<CondObj>> g_guest_conds;

    auto get_mutex_obj = [](uint32_t gptr) -> MutexObj* {
        std::lock_guard<std::mutex> lk(g_pt_mutex);
        auto& m = g_guest_mutexes[gptr];
        if (!m) m = std::make_unique<MutexObj>();
        return m.get();
    };
    auto get_cond_obj = [](uint32_t gptr) -> CondObj* {
        std::lock_guard<std::mutex> lk(g_pt_mutex);
        auto& c = g_guest_conds[gptr];
        if (!c) c = std::make_unique<CondObj>();
        return c.get();
    };

    RegisterThunk("pthread_mutex_init", [get_mutex_obj](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        get_mutex_obj(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::mutex> lk(g_pt_mutex);
        g_guest_mutexes.erase(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_lock", [get_mutex_obj](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (IsNullGuestSyncObject(jit.Regs()[0])) { jit.Regs()[0] = 0; return; }
        MutexObj* m = get_mutex_obj(jit.Regs()[0]);
        m->mtx.lock();
        m->owner.store(static_cast<int64_t>(gettid()));
        m->locked.fetch_add(1);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_unlock", [get_mutex_obj](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (IsNullGuestSyncObject(jit.Regs()[0])) { jit.Regs()[0] = 0; return; }
        // Unlock of a key this thread does not hold is a no-op: the game locks a
        // wrapper object and unlocks an inner one (Scaleform sync wrappers), so
        // the keys legitimately differ. Releasing another thread's hold here
        // would corrupt the pairing and leave the real owner stuck.
        MutexObj* m = get_mutex_obj(jit.Regs()[0]);
        if (m->owner.load() == static_cast<int64_t>(gettid()) && m->locked.load() > 0) {
            m->locked.fetch_sub(1);
            if (m->locked.load() == 0) m->owner.store(0);
            m->mtx.unlock();
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_trylock", [get_mutex_obj](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (IsNullGuestSyncObject(jit.Regs()[0])) { jit.Regs()[0] = 0; return; }
        MutexObj* m = get_mutex_obj(jit.Regs()[0]);
        bool ok = m->mtx.try_lock();
        if (ok) {
            m->owner.store(static_cast<int64_t>(gettid()));
            m->locked.fetch_add(1);
        }
        jit.Regs()[0] = ok ? 0 : 16; // EBUSY
    });

    RegisterThunk("pthread_mutexattr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_mutexattr_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_mutexattr_settype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_mutexattr_gettype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    RegisterThunk("pthread_cond_init", [get_cond_obj](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        get_cond_obj(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_cond_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::mutex> lk(g_pt_mutex);
        g_guest_conds.erase(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });
    // bionic semantics: cond_wait atomically releases the guest mutex while
    // blocked and re-acquires it before returning. The Scaleform protocol
    // relies on this — the signaller locks the same mutex to signal (see
    // sub_157F64: lock/signal/unlock), so a cond_wait that keeps the host
    // mutex held deadlocks (signaller blocks in mutex_lock forever).
    //
    // Both waits drop the guest mutex the same way, so share the bookkeeping.
    auto release_guest_mutex = [get_mutex_obj](uint32_t mtx_a) -> int {
        if (!mtx_a) return 0;
        MutexObj* m = get_mutex_obj(mtx_a);
        if (m->owner.load() != static_cast<int64_t>(gettid())) return 0;
        int held = m->locked.exchange(0);
        m->owner.store(0);
        for (int i = 0; i < held; ++i) m->mtx.unlock();
        return held;
    };
    auto reacquire_guest_mutex = [get_mutex_obj](uint32_t mtx_a, int held) {
        if (!mtx_a || !held) return;
        MutexObj* m = get_mutex_obj(mtx_a);
        for (int i = 0; i < held; ++i) m->mtx.lock();
        m->owner.store(static_cast<int64_t>(gettid()));
        m->locked.store(held);
    };
    RegisterThunk("pthread_cond_wait", [get_cond_obj, release_guest_mutex, reacquire_guest_mutex](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (IsNullGuestSyncObject(jit.Regs()[0])) { jit.Regs()[0] = 0; return; }
        CondObj* c = get_cond_obj(jit.Regs()[0]);
        uint32_t mtx_a = jit.Regs()[1];
        int held = release_guest_mutex(mtx_a);
        {
            std::unique_lock<std::mutex> lk(c->wait_mtx);
            // Bounded wait: the game's sync protocol can lose signals (custom
            // wrapper objects), and waking every 20ms lets its re-check loops
            // make progress instead of deadlocking.
            if (c->sticky.exchange(0) == 0) c->cv.wait_for(lk, std::chrono::milliseconds(20));
        }
        reacquire_guest_mutex(mtx_a, held);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_cond_timedwait", [get_cond_obj, release_guest_mutex, reacquire_guest_mutex](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (IsNullGuestSyncObject(jit.Regs()[0])) { jit.Regs()[0] = 0; return; }
        CondObj* c = get_cond_obj(jit.Regs()[0]);
        uint32_t mtx_a = jit.Regs()[1];
        uint32_t ts_guest = jit.Regs()[2];
        uint32_t sec = ts_guest ? host.MemoryRead32(ts_guest) : 0;
        uint32_t nsec = ts_guest ? host.MemoryRead32(ts_guest + 4) : 0;
        int held = release_guest_mutex(mtx_a);
        std::cv_status res = std::cv_status::no_timeout;
        {
            std::unique_lock<std::mutex> lk(c->wait_mtx);
            if (c->sticky.exchange(0) == 0)
                res = c->cv.wait_for(lk, std::chrono::seconds(sec) + std::chrono::nanoseconds(nsec));
        }
        reacquire_guest_mutex(mtx_a, held);
        jit.Regs()[0] = (res == std::cv_status::timeout) ? 110 /* ETIMEDOUT */ : 0;
    });
    RegisterThunk("pthread_cond_broadcast", [get_cond_obj](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (IsNullGuestSyncObject(jit.Regs()[0])) { jit.Regs()[0] = 0; return; }
        CondObj* c = get_cond_obj(jit.Regs()[0]);
        c->sticky.fetch_add(1);
        c->cv.notify_all();
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_cond_signal", [get_cond_obj](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (IsNullGuestSyncObject(jit.Regs()[0])) { jit.Regs()[0] = 0; return; }
        CondObj* c = get_cond_obj(jit.Regs()[0]);
        c->sticky.fetch_add(1);
        c->cv.notify_one();
        jit.Regs()[0] = 0;
    });

    // POSIX Semaphores
    RegisterThunk("sem_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        uint32_t val = jit.Regs()[2];
        if (sem_ptr) host.MemoryWrite32(sem_ptr, val);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("sem_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            if (val > 0) host.MemoryWrite32(sem_ptr, val - 1);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_trywait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            if (val > 0) {
                host.MemoryWrite32(sem_ptr, val - 1);
                jit.Regs()[0] = 0;
                return;
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_post", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            host.MemoryWrite32(sem_ptr, val + 1);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_getvalue", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        uint32_t sval_ptr = jit.Regs()[1];
        if (sem_ptr && sval_ptr) {
            host.MemoryWrite32(sval_ptr, host.MemoryRead32(sem_ptr));
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_once", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t control_addr = jit.Regs()[0];
        uint32_t init_routine = jit.Regs()[1];
        uint32_t control_val = control_addr ? host.MemoryRead32(control_addr) : 1;
        if (control_addr) host.MemoryWrite32(control_addr, 1);
        if (control_val == 0 && init_routine) {
            jit.Regs()[15] = init_routine & ~1u;
            if (init_routine & 1) {
                jit.SetCpsr(jit.Cpsr() | 0x20);
            } else {
                jit.SetCpsr(jit.Cpsr() & ~0x20);
            }
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_key_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key_ptr = jit.Regs()[0];
        if (key_ptr) host.MemoryWrite32(key_ptr, g_next_tls_key++);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_setspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key = jit.Regs()[0];
        uint32_t val = jit.Regs()[1];
        g_tls_map[key] = reinterpret_cast<void*>(static_cast<uintptr_t>(val));
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_getspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key = jit.Regs()[0];
        auto it = g_tls_map.find(key);
        jit.Regs()[0] = (it != g_tls_map.end()) ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(it->second)) : 0;
    });

    static auto ResolveGuestPath = [](const char* path) -> std::string {
        if (!path || !path[0]) return "";
        struct stat st;
        if (stat(path, &st) == 0) return std::string(path);

        const char* bname = strrchr(path, '/');
        bname = bname ? bname + 1 : path;
        const char* search_dirs[] = {
            "/storage/emulated/0/Android/data/com.roviostars.tinythief/files/",
            "/data/user/0/com.roviostars.tinythief/files/",
            "/data/data/com.roviostars.tinythief/files/",
            "/data/local/tmp/",
            "/sdcard/"
        };
        for (const char* dir : search_dirs) {
            std::string full = std::string(dir) + bname;
            if (stat(full.c_str(), &st) == 0) {
                return full;
            }
        }
        for (const char* dir : search_dirs) {
            std::string full = std::string(dir) + path;
            if (stat(full.c_str(), &st) == 0) {
                return full;
            }
        }
        return std::string(path);
    };

    // Standard I/O & Filesystem
    RegisterThunk("fopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* raw_path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* mode = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!raw_path) { jit.Regs()[0] = 0; return; }

        std::string resolved = ResolveGuestPath(raw_path);
        FILE* f = fopen(resolved.c_str(), mode ? mode : "r");
        if (f) {
            uint32_t handle = g_next_file_handle++;
            g_file_map[handle] = f;
            jit.Regs()[0] = handle;
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("fdopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const char* mode = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        FILE* f = fdopen(fd, mode);
        if (f) {
            uint32_t handle = g_next_file_handle++;
            g_file_map[handle] = f;
            jit.Regs()[0] = handle;
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("fclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) {
            fclose(it->second);
            g_file_map.erase(it);
            jit.Regs()[0] = 0;
        } else {
            jit.Regs()[0] = -1;
        }
    });

    RegisterThunk("fread", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        auto it = g_file_map.find(handle);
        size_t res = (it != g_file_map.end() && ptr) ? fread(ptr, size, count, it->second) : 0;
        jit.Regs()[0] = res;
    });

    RegisterThunk("fwrite", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end() && ptr) ? fwrite(ptr, size, count, it->second) : 0;
    });

    RegisterThunk("fseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        long offset = static_cast<long>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        auto it = g_file_map.find(handle);
        int res = (it != g_file_map.end()) ? fseek(it->second, offset, whence) : -1;
        jit.Regs()[0] = res;
    });

    RegisterThunk("fseeko", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        auto it = g_file_map.find(handle);
        int res = (it != g_file_map.end()) ? fseeko(it->second, offset, whence) : -1;
        jit.Regs()[0] = res;
    });

    RegisterThunk("ftell", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? static_cast<uint32_t>(ftell(it->second)) : 0;
    });

    RegisterThunk("ftello", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        off_t res = (it != g_file_map.end()) ? ftello(it->second) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("fileno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? fileno(it->second) : -1;
    });

    RegisterThunk("clearerr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) clearerr(it->second);
    });

    RegisterThunk("ferror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? ferror(it->second) : 0;
    });

    RegisterThunk("open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* raw_path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int flags = static_cast<int>(jit.Regs()[1]);
        int mode = static_cast<int>(jit.Regs()[2]);
        if (!raw_path) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }

        if (strcmp(raw_path, "/proc/cpuinfo") == 0) {
            int cfd = OpenSyntheticCpuInfo();
            LOGI("open: '/proc/cpuinfo' -> synthetic ARMv7 cpuinfo (fd %d)", cfd);
            jit.Regs()[0] = (cfd >= 0) ? static_cast<uint32_t>(cfd) : static_cast<uint32_t>(-1);
            return;
        }
        std::string resolved = ResolveGuestPath(raw_path);
        int fd = open(resolved.c_str(), flags, mode);
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(fd) : static_cast<uint32_t>(-1);
    });

    RegisterThunk("close", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(close(fd)) : static_cast<uint32_t>(-1);
    });

    RegisterThunk("read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        ssize_t res = (buf && fd >= 0) ? read(fd, buf, count) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        ssize_t res = (buf && fd >= 0) ? write(fd, buf, count) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        off_t res = (fd >= 0) ? lseek(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek64", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        off64_t offset = static_cast<off64_t>(static_cast<uint64_t>(jit.Regs()[2]) | (static_cast<uint64_t>(jit.Regs()[3]) << 32));
        int whence = static_cast<int>(host.MemoryRead32(jit.Regs()[13]));
        off64_t res = (fd >= 0) ? lseek64(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(res >> 32);
    });

    RegisterThunk("access", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* raw_path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int mode = static_cast<int>(jit.Regs()[1]);
        if (!raw_path) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        std::string resolved = ResolveGuestPath(raw_path);
        int res = access(resolved.c_str(), mode);
        jit.Regs()[0] = res;
    });

    RegisterThunk("stat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* raw_path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t buf_gaddr = jit.Regs()[1];
        if (!raw_path) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        std::string resolved = ResolveGuestPath(raw_path);
        struct stat st;
        int res = stat(resolved.c_str(), &st);
        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("fstat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t buf_gaddr = jit.Regs()[1];
        struct stat st;
        int res = fstat(fd, &st);
        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("remove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = remove(path ? path : "");
    });

    RegisterThunk("rename", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* oldp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* newp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = rename(oldp ? oldp : "", newp ? newp : "");
    });

    RegisterThunk("chmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("umask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("mkstemp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = -1; });
    RegisterThunk("getpid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = getpid(); });

    RegisterThunk("time", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(time(nullptr));
    });

    RegisterThunk("localtime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        time_t t = static_cast<time_t>(host.MemoryRead32(jit.Regs()[0]));
        struct tm* tm_res = localtime(&t);
        if (tm_res) {
            uint32_t gtm = host.GuestAlloc(sizeof(struct tm));
            memcpy(GuestToHost(host.GetGuestMemoryBase(), gtm), tm_res, sizeof(struct tm));
            jit.Regs()[0] = gtm;
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("mktime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        struct tm* tm_ptr = reinterpret_cast<struct tm*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = tm_ptr ? static_cast<uint32_t>(mktime(tm_ptr)) : 0;
    });

    RegisterThunk("raise", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Runtime guards & hooks
    RegisterThunk("__stack_chk_fail", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("Guest stack check failed at PC: 0x%08X", jit.Regs()[15]);
    });

    RegisterThunk("abort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("Guest called abort()!");
    });

    RegisterThunk("__assert2", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* file = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int line = static_cast<int>(jit.Regs()[1]);
        const char* func = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        const char* expr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        LOGE("Assertion failed: %s at %s:%d (%s)", expr ? expr : "", file ? file : "", line, func ? func : "");
    });

    RegisterThunk("__cxa_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_finalize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__aeabi_unwind_cpp_pr0", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("__aeabi_unwind_cpp_pr1", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_RaiseException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_DeleteException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_GetLanguageSpecificData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_GetRegionStart", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Set", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__gnu_unwind_frame", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // -------------------------------------------------------------
    // Tiny Thief additions: ctype, strings, dirs, mmap family, setjmp
    // -------------------------------------------------------------
    RegisterThunk("isalnum", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = isalnum((int)jit.Regs()[0]); });
    RegisterThunk("isalpha", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = isalpha((int)jit.Regs()[0]); });
    RegisterThunk("iscntrl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = iscntrl((int)jit.Regs()[0]); });
    RegisterThunk("isgraph", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = isgraph((int)jit.Regs()[0]); });
    RegisterThunk("isprint", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = isprint((int)jit.Regs()[0]); });
    RegisterThunk("ispunct", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = ispunct((int)jit.Regs()[0]); });
    RegisterThunk("isspace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = isspace((int)jit.Regs()[0]); });
    RegisterThunk("isupper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = isupper((int)jit.Regs()[0]); });
    RegisterThunk("tolower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = tolower((int)jit.Regs()[0]); });
    RegisterThunk("toupper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = toupper((int)jit.Regs()[0]); });

    RegisterThunk("strchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int c = (int)jit.Regs()[1];
        if (!s) { jit.Regs()[0] = 0; return; }
        const char* res = strchr(s, c);
        jit.Regs()[0] = res ? HostToGuest(host.GetGuestMemoryBase(), const_cast<char*>(res)) : 0;
    });
    RegisterThunk("strstr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* n = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!s || !n) { jit.Regs()[0] = 0; return; }
        const char* res = strstr(s, n);
        jit.Regs()[0] = res ? HostToGuest(host.GetGuestMemoryBase(), const_cast<char*>(res)) : 0;
    });
    RegisterThunk("strcspn", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* r = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s && r) ? static_cast<uint32_t>(strcspn(s, r)) : 0;
    });
    RegisterThunk("strspn", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* a = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s && a) ? static_cast<uint32_t>(strspn(s, a)) : 0;
    });
    RegisterThunk("strtok", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        // Single-threaded guest usage; emulate with host strtok
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* d = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        char* res = strtok(const_cast<char*>(s), const_cast<char*>(d));
        jit.Regs()[0] = res ? HostToGuest(host.GetGuestMemoryBase(), res) : 0;
    });
    RegisterThunk("strtod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t endptr = jit.Regs()[1];
        char* end = nullptr;
        double v = s ? strtod(s, &end) : 0.0;
        if (endptr) host.MemoryWrite32(endptr, end ? HostToGuest(host.GetGuestMemoryBase(), end) : 0);
        WriteDF(jit, 0, v);
    });
    RegisterThunk("strtoull", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int base = (int)jit.Regs()[2];
        uint64_t v = s ? strtoull(s, nullptr, base) : 0;
        jit.Regs()[0] = static_cast<uint32_t>(v & 0xFFFFFFFFu);
        jit.Regs()[1] = static_cast<uint32_t>(v >> 32);
    });
    RegisterThunk("wcscmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* a = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* b = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (a && b) ? wcscmp(a, b) : 0;
    });
    RegisterThunk("wcscoll", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const wchar_t* a = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const wchar_t* b = reinterpret_cast<const wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (a && b) ? wcscoll(a, b) : 0;
    });

    RegisterThunk("getenv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::map<std::string, uint32_t> s_env_cache;
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!name) { jit.Regs()[0] = 0; return; }
        auto it = s_env_cache.find(name);
        if (it != s_env_cache.end()) { jit.Regs()[0] = it->second; return; }
        const char* val = getenv(name);
        if (!val) { jit.Regs()[0] = 0; return; }
        uint32_t g = host.GuestAlloc(strlen(val) + 1);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + g), val);
        s_env_cache[name] = g;
        jit.Regs()[0] = g;
    });
    RegisterThunk("sysconf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(sysconf((int)jit.Regs()[0]));
    });
    RegisterThunk("gmtime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        time_t t = static_cast<time_t>(jit.Regs()[0]);
        struct tm* tm_res = gmtime(&t);
        if (tm_res) {
            uint32_t gtm = host.GuestAlloc(sizeof(struct tm));
            memcpy(GuestToHost(host.GetGuestMemoryBase(), gtm), tm_res, sizeof(struct tm));
            jit.Regs()[0] = gtm;
        } else jit.Regs()[0] = 0;
    });
    RegisterThunk("fflush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? fflush(it->second) : 0;
    });
    RegisterThunk("rewind", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) rewind(it->second);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("putchar", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = (int)jit.Regs()[0]; });
    RegisterThunk("dup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(dup((int)jit.Regs()[0]));
    });
    RegisterThunk("exit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("Guest called exit(%d)!", (int)jit.Regs()[0]);
        jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
    });

    // ---- directories ----
    static std::unordered_map<uint32_t, DIR*> g_dir_map;
    static uint32_t g_next_dir_handle = 0x10002000;
    RegisterThunk("opendir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        DIR* d = path ? opendir(path) : nullptr;
        if (d) {
            uint32_t h = g_next_dir_handle++;
            g_dir_map[h] = d;
            jit.Regs()[0] = h;
        } else jit.Regs()[0] = 0;
    });
    RegisterThunk("readdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t h = jit.Regs()[0];
        auto it = g_dir_map.find(h);
        if (it == g_dir_map.end()) { jit.Regs()[0] = 0; return; }
        struct dirent* de = readdir(it->second);
        if (!de) { jit.Regs()[0] = 0; return; }
        static uint32_t s_prev_dirent = 0;
        // one guest dirent at a time (guest usually copies d_name immediately)
        uint32_t g = host.GuestAlloc(512, 4);
        memset(host.GetGuestMemoryBase() + g, 0, 512);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + g + 11), de->d_name); // arm dirent: d_name at +11
        jit.Regs()[0] = g;
    });
    RegisterThunk("closedir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t h = jit.Regs()[0];
        auto it = g_dir_map.find(h);
        if (it != g_dir_map.end()) { closedir(it->second); g_dir_map.erase(it); }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("mkdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (path) mkdir(path, 0755);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("fnmatch", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* p = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        // minimal * ? matcher (fnmatch.h not exported on android-26)
        auto match = [](const char* pat, const char* str, auto&& self) -> bool {
            if (!*pat) return !*str;
            if (*pat == '*') {
                while (*pat == '*') ++pat;
                if (!*pat) return true;
                for (const char* t = str; *t; ++t)
                    if (self(pat, t, self)) return true;
                return self(pat, str + strlen(str), self);
            }
            if (!*str) return false;
            if (*pat == '?' || *pat == *str) return self(pat + 1, str + 1, self);
            return false;
        };
        jit.Regs()[0] = (p && s && match(p, s, match)) ? 0 : 1;
    });

    // ---- mmap family (guest-heap backed) ----
    RegisterThunk("mmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t hint = jit.Regs()[0];
        size_t len = jit.Regs()[1];
        int prot = (int)jit.Regs()[2];
        int flags = (int)jit.Regs()[3];
        if (!len) { jit.Regs()[0] = 0; return; }
        uint32_t g = host.GuestAlloc(len, 4096);
        if (hint && flags & 0x10 /* MAP_FIXED */) g = hint;
        memset(host.GetGuestMemoryBase() + g, 0, len);
        jit.Regs()[0] = g;
    });
    RegisterThunk("munmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("mremap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t old_addr = jit.Regs()[0];
        size_t old_size = jit.Regs()[1];
        size_t new_size = jit.Regs()[2];
        uint32_t g = host.GuestAlloc(new_size, 4096);
        if (old_addr && old_size) {
            memcpy(host.GetGuestMemoryBase() + g, host.GetGuestMemoryBase() + old_addr,
                   old_size < new_size ? old_size : new_size);
        }
        jit.Regs()[0] = g;
    });

    // ---- setjmp/longjmp via host jmp_buf (guest regs are host memory, longjmp unwinds C++ stack) ----
    static std::unordered_map<uint32_t, std::pair<jmp_buf, bool>> g_jmp_map;
    RegisterThunk("setjmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t guest_buf = jit.Regs()[0];
        if (!guest_buf) { jit.Regs()[0] = 1; return; }
        auto& slot = g_jmp_map[guest_buf];
        int v = setjmp(slot.first);
        slot.second = (v == 0); // marker that setjmp executed
        jit.Regs()[0] = static_cast<uint32_t>(v);
    });
    RegisterThunk("longjmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t guest_buf = jit.Regs()[0];
        int val = (int)jit.Regs()[1];
        auto it = g_jmp_map.find(guest_buf);
        if (it == g_jmp_map.end() || !it->second.second) {
            LOGE("longjmp to unknown/unsaved buffer 0x%08X!", guest_buf);
            jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
            return;
        }
        longjmp(it->second.first, val ? val : 1);
    });

    // ---- cxa guards ----
    static std::unordered_map<uint32_t, bool> g_guards;
    RegisterThunk("__cxa_guard_acquire", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t g = jit.Regs()[0];
        if (host.MemoryRead8(g) != 0) { jit.Regs()[0] = 0; return; }
        if (g_guards[g]) { jit.Regs()[0] = 0; return; } // someone else initializing
        g_guards[g] = true;
        jit.Regs()[0] = 1;
    });
    RegisterThunk("__cxa_guard_release", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t g = jit.Regs()[0];
        g_guards[g] = false;
        host.MemoryWrite8(g, 1);
        jit.Regs()[0] = 0;
    });

    // ---- unwind support: exidx lookup for guest modules ----
    RegisterThunk("__gnu_Unwind_Find_exidx", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t pc = jit.Regs()[0];
        uint32_t out_start = jit.Regs()[1];
        uint32_t exidx = 0, exidx_size = 0;
        uint32_t base = host.GetElfLoader().GetBaseAddress();
        if (pc >= base && pc < host.GetElfLoader().GetImageEnd()) {
            exidx = host.GetElfLoader().GetArmExidxAddr();
            exidx_size = host.GetElfLoader().GetArmExidxSize();
        } else if (host.GetFModExLoader() &&
                   pc >= host.GetFModExLoader()->GetBaseAddress() && pc < host.GetFModExLoader()->GetImageEnd()) {
            exidx = host.GetFModExLoader()->GetArmExidxAddr();
            exidx_size = host.GetFModExLoader()->GetArmExidxSize();
        }
        if (exidx && out_start) {
            host.MemoryWrite32(out_start, exidx);
            host.MemoryWrite32(out_start + 4, exidx + exidx_size);
        }
        jit.Regs()[0] = exidx;
    });

    // ---- long<->float AEABI helpers (softfp: values in core registers) ----
    RegisterThunk("__aeabi_f2lz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t v = static_cast<int64_t>(ReadSF(jit, 0));
        jit.Regs()[0] = static_cast<uint32_t>(v & 0xFFFFFFFFu);
        jit.Regs()[1] = static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32);
    });
    RegisterThunk("__aeabi_f2ulz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t v = static_cast<uint64_t>(ReadSF(jit, 0));
        jit.Regs()[0] = static_cast<uint32_t>(v & 0xFFFFFFFFu);
        jit.Regs()[1] = static_cast<uint32_t>(v >> 32);
    });
    RegisterThunk("__aeabi_d2lz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t v = static_cast<int64_t>(ReadDF(jit, 0));
        jit.Regs()[0] = static_cast<uint32_t>(v & 0xFFFFFFFFu);
        jit.Regs()[1] = static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32);
    });
    RegisterThunk("__aeabi_d2ulz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t v = static_cast<uint64_t>(ReadDF(jit, 0));
        jit.Regs()[0] = static_cast<uint32_t>(v & 0xFFFFFFFFu);
        jit.Regs()[1] = static_cast<uint32_t>(v >> 32);
    });
    RegisterThunk("__aeabi_l2d", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t v = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        WriteDF(jit, 0, static_cast<double>(v));
    });
    RegisterThunk("__aeabi_l2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t v = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        WriteSF(jit, 0, static_cast<float>(v));
    });
    RegisterThunk("__aeabi_ul2d", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t v = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        WriteDF(jit, 0, static_cast<double>(v));
    });
    RegisterThunk("__aeabi_ul2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t v = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        WriteSF(jit, 0, static_cast<float>(v));
    });

    // ---- networking extras ----
    RegisterThunk("sendto", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = (int)jit.Regs()[0];
        const void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t len = jit.Regs()[2];
        int flags = (int)jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        const sockaddr* addr = reinterpret_cast<const sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp)));
        socklen_t alen = host.MemoryRead32(sp + 4);
        jit.Regs()[0] = static_cast<uint32_t>(sendto(fd, buf, len, flags, addr, alen));
    });
    RegisterThunk("recvfrom", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = (int)jit.Regs()[0];
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t len = jit.Regs()[2];
        int flags = (int)jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        sockaddr* addr = reinterpret_cast<sockaddr*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp)));
        uint32_t alen_ptr = host.MemoryRead32(sp + 4);
        socklen_t alen = alen_ptr ? host.MemoryRead32(alen_ptr) : 0;
        ssize_t r = recvfrom(fd, buf, len, flags, addr, addr ? &alen : nullptr);
        if (alen_ptr) host.MemoryWrite32(alen_ptr, alen);
        jit.Regs()[0] = static_cast<uint32_t>(r);
    });
    RegisterThunk("shutdown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(shutdown((int)jit.Regs()[0], (int)jit.Regs()[1]));
    });
    RegisterThunk("pthread_exit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
    });
    RegisterThunk("vsprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
}
