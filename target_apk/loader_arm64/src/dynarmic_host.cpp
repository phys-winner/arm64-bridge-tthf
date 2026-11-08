// SPDX-License-Identifier: GPL-3.0-or-later
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include <cstring>
#include <algorithm>
#include <mutex>
#include <unordered_map>
#include <android/log.h>
#include <dynarmic/interface/A32/coprocessor.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define LOG_TAG "TT_ARM64_Loader"
#include "bridge_logging.h"

// Guest code stores through null pointers here and there (Scaleform queue
// waiter lists in particular), so the first page must stay ordinary RW memory.
// Keep the RunFunction exit trap on its own page just below the thunk area
// instead, where nothing else writes.
#define EXIT_TRAP_ADDRESS 0x0000F004
#define EXIT_TRAP_BASE    0x0000F000

// The Jit currently executing on this host thread. Set around Jit::Run so the
// SVC/exception callbacks (which get no Jit argument) can reach it.
static thread_local Dynarmic::A32::Jit* t_running_jit = nullptr;

DynarmicHost::DynarmicHost() = default;

DynarmicHost::~DynarmicHost() {
    if (m_memory) {
#if defined(_WIN32)
        VirtualFree(m_memory, 0, MEM_RELEASE);
#else
        munmap(m_memory, m_memory_size);
#endif
        m_memory = nullptr;
    }
}

// Reserve guest memory. MAP_NORESERVE keeps the 4 GiB reservation virtual: untouched pages
// cost nothing and only written pages are ever committed.
static uint8_t* MapGuestMemory(size_t size) {
#if defined(_WIN32)
    return reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
#else
    void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? nullptr : reinterpret_cast<uint8_t*>(p);
#endif
}

bool DynarmicHost::Initialize() {
    // Mapping the whole 32-bit space lets the JIT emit a single `ldr Wt, [Xfastmem, Waddr, uxtw]`
    // per guest access instead of a call into MemoryRead*/MemoryWrite*.
    m_memory_size = GUEST_ADDRESS_SPACE;
    m_memory = MapGuestMemory(m_memory_size);
    m_fastmem = m_memory != nullptr;
    if (!m_memory) {
        LOGE("Could not reserve %zu bytes for the guest address space; "
             "falling back to %zu bytes without fastmem.", GUEST_ADDRESS_SPACE, GUEST_FALLBACK_SIZE);
        m_memory_size = GUEST_FALLBACK_SIZE;
        m_memory = MapGuestMemory(m_memory_size);
        if (!m_memory) {
            LOGE("Failed to allocate guest memory (%zu bytes)", m_memory_size);
            m_memory_size = 0;
            return false;
        }
    }

    HeapSelfCheck();

    // Exit traps (ARM SVC 0 = 0xEF000000) for RunFunction returns.
    for (uint32_t addr = EXIT_TRAP_BASE; addr < EXIT_TRAP_BASE + 0x40; addr += 4) {
        *reinterpret_cast<uint32_t*>(m_memory + addr) = 0xEF000000;
    }
    // A jump through a null function pointer should stop the guest too.
    for (uint32_t addr = 0; addr < 0x40; addr += 4) {
        *reinterpret_cast<uint32_t*>(m_memory + addr) = 0xEF000000;
    }

    // The JIT dereferences global_monitor unconditionally for LDREX/STREX, so it must exist
    // before any Jit is created.
    m_monitor = std::make_unique<Dynarmic::ExclusiveMonitor>(MAX_GUEST_CORES);

    m_thunk_manager = std::make_unique<ThunkManager>(*this);
    m_thunk_manager->RegisterAllThunks();

    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);

    LOGI("Dynarmic Host initialized: %zu bytes guest space, fastmem %s",
         m_memory_size, m_fastmem ? "ON" : "OFF");
    return true;
}

// The guest queries coprocessors (CP15 system-control reads and friends).
// dynarmic asserts on unhandled coprocessor instructions instead of raising an
// exception, so every slot needs a handler; reading zero is harmless here.
class StubCoprocessor : public Dynarmic::A32::Coprocessor {
public:
    using CoprocReg = Dynarmic::A32::CoprocReg;

    static uint64_t Zero(void*, uint32_t, uint32_t) { return 0; }
    static Callback ZeroCallback() { return Callback{&StubCoprocessor::Zero, nullptr}; }

    std::optional<Callback> CompileInternalOperation(bool, unsigned, CoprocReg, CoprocReg, CoprocReg, unsigned) override {
        return ZeroCallback();
    }
    CallbackOrAccessOneWord CompileSendOneWord(bool, unsigned, CoprocReg, CoprocReg, unsigned) override {
        return ZeroCallback();
    }
    CallbackOrAccessTwoWords CompileSendTwoWords(bool, unsigned, CoprocReg) override {
        return ZeroCallback();
    }
    CallbackOrAccessOneWord CompileGetOneWord(bool, unsigned, CoprocReg, CoprocReg, unsigned) override {
        return ZeroCallback();
    }
    CallbackOrAccessTwoWords CompileGetTwoWords(bool, unsigned, CoprocReg) override {
        return ZeroCallback();
    }
    std::optional<Callback> CompileLoadWords(bool, bool, CoprocReg, std::optional<std::uint8_t>) override {
        return ZeroCallback();
    }
    std::optional<Callback> CompileStoreWords(bool, bool, CoprocReg, std::optional<std::uint8_t>) override {
        return ZeroCallback();
    }
};

std::unique_ptr<Dynarmic::A32::Jit> DynarmicHost::CreateJitInstance() {
    Dynarmic::A32::UserConfig config;
    config.callbacks = this;
    config.global_monitor = m_monitor.get();
    // Each Jit needs its own monitor slot; ids past the last one share, which the
    // compare-and-swap in MemoryWriteExclusive* still makes safe.
    config.processor_id = m_next_processor_id.fetch_add(1) % MAX_GUEST_CORES;
    config.arch_version = Dynarmic::A32::ArchVersion::v7;  // guest libs are ARMv7-A + NEON
    config.enable_cycle_counting = false;                  // no timing model; skips AddTicks emission
    config.always_little_endian = true;                    // guest never uses SETEND; drops CPSR.E handling
    config.define_unpredictable_behaviour = true;          // define rather than halt on odd encodings
    config.code_cache_size = 16 * 1024 * 1024;             // bounded per-thread JIT cache from the shared bridge
    if (m_fastmem) {
        config.fastmem_pointer = reinterpret_cast<uintptr_t>(m_memory);
    }
    static std::shared_ptr<StubCoprocessor> s_stub = std::make_shared<StubCoprocessor>();
    for (int i = 0; i < 16; ++i) config.coprocessors[i] = s_stub;
    return std::make_unique<Dynarmic::A32::Jit>(config);
}

// Audio latency. Scaleform's SoundRendererFMOD calls
// FMOD::System::setDSPBufferSize(1024, 9) — 9216 frames queued in the AudioTrack
// before a sound is heard, and at FMOD's default 24 kHz software rate that is
// 384 ms. It is a 2013 safety margin for slow phones and it was the whole of the
// audible input->sound delay. Two fixes, both applied from that one call site
// (it is the last thing the game does before System::init):
//   1. shrink the DSP buffer;
//   2. raise the software mixer to the device rate, so AudioFlinger does not
//      have to resample and the track stops taking the slow mixer path.
static constexpr uint32_t kFmodSampleRate = 48000;
static constexpr uint32_t kFmodDspBufferLength = 512; // 10.7 ms at 48 kHz
static constexpr uint32_t kFmodDspNumBuffers = 4;     // -> 42.7 ms queued

void DynarmicHost::PatchFmodDspBufferSize() {
    uint32_t fn = m_fmodex_loader->GetSymbolAddress("_ZN4FMOD6System16setDSPBufferSizeEji");
    uint32_t get_fmt = m_fmodex_loader->GetSymbolAddress(
        "_ZN4FMOD6System17getSoftwareFormatEPiP17FMOD_SOUND_FORMATS1_S1_P18FMOD_DSP_RESAMPLERS1_");
    uint32_t set_fmt = m_fmodex_loader->GetSymbolAddress(
        "_ZN4FMOD6System17setSoftwareFormatEi17FMOD_SOUND_FORMATii18FMOD_DSP_RESAMPLER");
    if (!fn) {
        LOGE("setDSPBufferSize not found in libfmodex.so — audio latency left as-is");
        return;
    }
    // Replace the prologue with an SVC; the handler rewrites the arguments and
    // emulates the PUSH so the rest of the function runs unchanged.
    uint32_t orig = MemoryRead32(fn);
    if ((orig & 0xFFFF0000) != 0xE92D0000) { // STMDB SP!, {regs}
        LOGE("setDSPBufferSize prologue is 0x%08X, not a PUSH — not patching", orig);
        return;
    }
    uint32_t thunk = m_thunk_manager->RegisterThunk("FMOD_setDSPBufferSize",
        [orig, get_fmt, set_fmt](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
            uint32_t system = jit.Regs()[0];
            if (get_fmt && set_fmt) {
                // Keep every other field the mixer was going to use; only the
                // sample rate changes. out[] = {rate, format, outCh, inCh, resampler, bits}
                uint32_t out = host.GuestAlloc(6 * 4, 4);
                for (int i = 0; i < 6; ++i) host.MemoryWrite32(out + i * 4, 0);
                host.RunFunctionNested(get_fmt, {system, out, out + 4, out + 8,
                                                 out + 12, out + 16, out + 20});
                host.RunFunctionNested(set_fmt, {system, kFmodSampleRate,
                                                 host.MemoryRead32(out + 4),
                                                 host.MemoryRead32(out + 8),
                                                 host.MemoryRead32(out + 12),
                                                 host.MemoryRead32(out + 16)});
                LOGI("FMOD software format %u Hz -> %u Hz", host.MemoryRead32(out), kFmodSampleRate);
            }
            jit.Regs()[1] = kFmodDspBufferLength;
            jit.Regs()[2] = kFmodDspNumBuffers;
            uint32_t regs = orig & 0xFFFF;
            uint32_t sp = jit.Regs()[13] - 4u * __builtin_popcount(regs);
            jit.Regs()[13] = sp;
            for (int r = 0; r < 16; ++r)
                if (regs & (1u << r)) { host.MemoryWrite32(sp, jit.Regs()[r]); sp += 4; }
        });
    MemoryWrite32(fn, 0xEF000000 | ((thunk - 0x00010000) / 8 + 1));
    LOGI("FMOD DSP buffer forced to %u x %u", kFmodDspBufferLength, kFmodDspNumBuffers);
}

bool DynarmicHost::LoadGameMemory(const std::vector<uint8_t>& game_elf_in, const std::vector<uint8_t>& fmodex_elf_in) {
    std::vector<uint8_t> game_elf = game_elf_in;
    const std::vector<uint8_t>& fmodex_elf = fmodex_elf_in;

    // Scaleform GFxFileOpener::OpenFile (0x72BE8) -> host asset loader.
    // Only the "assets://" branch is ours; every other URL must reach the
    // original base opener sub_19F428, which returns a real read/write SysFile
    // (SharedObject.flush() needs it, and a NULL there surfaces in
    // ActionScript as Error #1501).
    //   SVC #id        ; handler: r12=0 -> handled (r0 = file), r12=1 -> delegate
    //   CMP R12, #0
    //   BXEQ LR
    //   B   sub_19F428 ; r0..r3 untouched by the handler in the delegate case
    {
        uint32_t thunk_openfile = m_thunk_manager->RegisterThunk("GFxFileOpener_OpenFile",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                host.Thunk_GFxFileOpener_OpenFile(jit, host);
            });
        uint32_t thunk_id = (thunk_openfile - 0x00010000) / 8 + 1;
        constexpr uint32_t kBaseOpener = 0x19F428;
        uint32_t br_off = (kBaseOpener - (0x72BF4 + 8)) / 4;
        auto patch_word = [&](size_t off, uint32_t v) {
            *reinterpret_cast<uint32_t*>(game_elf.data() + off) = v;
        };
        patch_word(0x72BE8, 0xEF000000 | thunk_id);
        patch_word(0x72BEC, 0xE35C0000);
        patch_word(0x72BF0, 0x012FFF1E);
        patch_word(0x72BF4, 0xEA000000 | (br_off & 0x00FFFFFF));
        LOGI("Hooked Scaleform GFxFileOpener::OpenFile (0x72BE8) -> SVC #%u, fallback B 0x%X",
             thunk_id, kBaseOpener);
    }

    // 1. libfmodex.so at 0x40800000
    if (!fmodex_elf.empty()) {
        m_fmodex_loader = std::make_unique<ElfLoader>(m_memory, 0x40800000);
        if (m_fmodex_loader->LoadFromMemory(fmodex_elf.data(), fmodex_elf.size())) {
            auto fmodex_res = [this](const std::string& name) -> uint32_t {
                return m_thunk_manager->GetOrCreateThunkAddress(name);
            };
            m_fmodex_loader->Relocate(fmodex_res);
            PatchFmodDspBufferSize();
            for (uint32_t init : m_fmodex_loader->GetInitArray()) {
                RunFunction(init);
            }
            LOGI("FMOD Ex loaded at 0x40800000");
        } else {
            LOGE("Failed to load FMOD Ex from memory");
        }
    }

    // 2. libtinythief.so at 0x40000000
    if (!m_elf_loader->LoadFromMemory(game_elf.data(), game_elf.size())) {
        LOGE("Failed to load game ELF from memory");
        return false;
    }

    auto game_res = [this](const std::string& name) -> uint32_t {
        if (m_thunk_manager->HasThunk(name)) {
            return m_thunk_manager->GetOrCreateThunkAddress(name);
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_elf_loader->Relocate(game_res)) {
        LOGE("Failed to relocate ELF.");
        return false;
    }

    LOGI("Running %zu static initializers in .init_array...", m_elf_loader->GetInitArray().size());
    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Game library loaded and initialized successfully!");
    return true;
}

Dynarmic::A32::Jit& DynarmicHost::GetThreadJit() {
    thread_local std::unique_ptr<Dynarmic::A32::Jit> t_jit;
    if (!t_jit) t_jit = CreateJitInstance();
    return *t_jit;
}

uint32_t DynarmicHost::RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args) {
    if (!m_memory) return 0;
    // Each host thread needs its own guest stack: the game blocks threads inside
    // deep call chains and a shared stack region would corrupt their frames
    // (stack canaries fire -> __stack_chk_fail).
    thread_local uint32_t t_stack_top = 0;
    if (!t_stack_top) t_stack_top = AllocGuestStack(8 * 1024 * 1024);
    return RunFunctionOnJit(GetThreadJit(), t_stack_top, target_pc, args);
}

uint32_t DynarmicHost::RunFunctionNested(uint32_t target_pc, const std::vector<uint32_t>& args) {
    // ponytail: the Jit and its stack are thrown away after the call. Fine for
    // the handful of one-off setup calls this exists for; give it a pool if it
    // ever ends up on a hot path.
    auto jit = CreateJitInstance();
    return RunFunctionOnJit(*jit, AllocGuestStack(1024 * 1024), target_pc, args);
}

uint32_t DynarmicHost::RunFunctionOnJit(Dynarmic::A32::Jit& jit, uint32_t stack_top,
                                        uint32_t target_pc, const std::vector<uint32_t>& args) {
    // No global lock: each Jit instance is driven by exactly one host thread.
    // Save/restore: a thunk may call back into guest code (RunFunction), and
    // clearing this on the inner return would leave the outer guest run without
    // a Jit for SVC dispatch and halts.
    Dynarmic::A32::Jit* prev_running_jit = t_running_jit;
    t_running_jit = &jit;

    for (size_t i = 0; i < 16; ++i) jit.Regs()[i] = 0;

    jit.Regs()[13] = stack_top;
    if (args.size() > 4) {
        size_t extra_args = args.size() - 4;
        // AAPCS: SP must stay 8-byte aligned at a public interface.
        uint32_t sp = (stack_top - static_cast<uint32_t>(extra_args * 4)) & ~7u;
        jit.Regs()[13] = sp;
        for (size_t i = 0; i < extra_args; ++i) {
            *reinterpret_cast<uint32_t*>(m_memory + sp + i * 4) = args[4 + i];
        }
    }
    for (size_t i = 0; i < args.size() && i < 4; ++i) jit.Regs()[i] = args[i];

    jit.Regs()[14] = EXIT_TRAP_ADDRESS;

    bool is_thumb = (target_pc & 1) != 0;
    jit.Regs()[15] = target_pc & ~1u;
    jit.SetCpsr((jit.Cpsr() & ~0x20u) | (is_thumb ? 0x20u : 0u));

    jit.ClearHalt();
    jit.Run();
    t_running_jit = prev_running_jit;
    return jit.Regs()[0];
}

// -------------------------------------------------------------
// Guest heap
//
// Every block carries a 16-byte header immediately before its payload:
//   [-16] magic  [-12] block base  [-8] capacity  [-4] payload size
// The magic is what makes GuestFree safe: a pointer that does not carry it is
// not ours (module data, an interior pointer, a stack top, something the guest
// invented) and is ignored exactly like the old no-op free ignored everything.
// Freeing clears the magic, so a double free is ignored too.
// -------------------------------------------------------------
namespace {
constexpr uint32_t kBlockMagic  = 0x54544831; // 'TTH1' - live block
constexpr uint32_t kFreedMagic  = 0x54544846; // 'TTHF' - already on a free list
constexpr uint32_t kHeaderSize  = 16;
}

uint32_t DynarmicHost::GuestAlloc(size_t size, size_t alignment) {
    // Returning 0 is not an option: the guest treats a failed allocation as
    // fatal and corrupts itself.
    if (size == 0) size = 1;
    if (alignment < 8) alignment = 8;
    // Worst case layout: header, then up to a full alignment step of padding.
    uint64_t need = static_cast<uint64_t>(size) + alignment + kHeaderSize;

    uint32_t base = 0, capacity = 0;
    bool recycled = false;
    {
        std::lock_guard<std::mutex> lk(m_heap_mutex);
        if (need <= kMaxClassSize) {
            int cls = 0;
            while ((1u << (cls + kMinClassShift)) < need) ++cls;
            capacity = 1u << (cls + kMinClassShift);
            auto& fl = m_free_small[cls];
            if (!fl.empty()) { base = fl.back(); fl.pop_back(); recycled = true; }
        } else {
            capacity = static_cast<uint32_t>((need + 15) & ~15ull);
            auto it = m_free_huge.find(capacity);
            if (it != m_free_huge.end() && !it->second.empty()) {
                base = it->second.back();
                it->second.pop_back();
                recycled = true;
            }
        }
        if (!recycled) {
            base = m_heap_current;
            if (static_cast<uint64_t>(base) + capacity > m_memory_size) {
                static bool warned = false;
                if (!warned) {
                    warned = true;
                    LOGE("Guest heap exhausted at 0x%08X (+%u bytes, arena %zu)", base, capacity, m_memory_size);
                }
            }
            m_heap_current = base + capacity;
        }
    }

    uint32_t payload = static_cast<uint32_t>(
        (static_cast<uint64_t>(base) + kHeaderSize + alignment - 1) & ~(static_cast<uint64_t>(alignment) - 1));
    if (recycled && static_cast<uint64_t>(payload) + size <= m_memory_size) {
        // Fresh arena memory has always been zero, and guest code that leaned on
        // that would break in confusing ways the first time it saw a recycled
        // block. Cheap insurance: ~3 MB/s of memset at the observed churn.
        memset(m_memory + payload, 0, size);
    }
    MemoryWrite32(payload - 16, kBlockMagic);
    MemoryWrite32(payload - 12, base);
    MemoryWrite32(payload - 8, capacity);
    MemoryWrite32(payload - 4, static_cast<uint32_t>(size));
    return payload;
}

uint32_t DynarmicHost::GuestAllocSize(uint32_t addr) {
    if (addr < kHeapBase + kHeaderSize) return 0;
    if (MemoryRead32(addr - 16) != kBlockMagic) return 0;
    return MemoryRead32(addr - 4);
}

// Runs once at startup. A silently wrong allocator corrupts the guest far away
// from the cause, so pay a few microseconds to fail loudly at the source.
void DynarmicHost::HeapSelfCheck() {
#define TT_CHECK(cond) do { if (!(cond)) { LOGE("HeapSelfCheck FAILED: %s", #cond); ok = false; } } while (0)
    bool ok = true;

    uint32_t a = GuestAlloc(100, 8);
    uint32_t b = GuestAlloc(100, 8);
    TT_CHECK(a != 0 && b != 0 && a != b);
    TT_CHECK((a & 7) == 0 && (b & 7) == 0);
    TT_CHECK(a + 100 <= b - kHeaderSize || b + 100 <= a - kHeaderSize); // no overlap
    TT_CHECK(GuestAllocSize(a) == 100);

    uint32_t aligned = GuestAlloc(64, 0x1000);
    TT_CHECK(aligned != 0 && (aligned & 0xFFF) == 0);

    // Freed blocks come back; the payload is handed over zeroed.
    MemoryWrite32(a, 0xDEADBEEF);
    GuestFree(a);
    TT_CHECK(GuestAllocSize(a) == 0);          // magic cleared
    GuestFree(a);                              // double free: must be a no-op
    uint32_t reused = GuestAlloc(100, 8);
    TT_CHECK(reused == a);
    TT_CHECK(MemoryRead32(reused) == 0);

    // Pointers we did not hand out must be ignored, not recycled.
    GuestFree(0x40000000);
    GuestFree(kHeapBase + 4);
    GuestFree(b + 8);                          // interior pointer
    TT_CHECK(GuestAllocSize(b) == 100);        // b survived all of that

    // Large blocks recycle by exact capacity rather than rounding to a power of two.
    uint32_t big = GuestAlloc(8 * 1024 * 1024, 0x10000);
    TT_CHECK(big != 0 && (big & 0xFFFF) == 0);
    GuestFree(big);
    uint32_t big2 = GuestAlloc(8 * 1024 * 1024, 0x10000);
    TT_CHECK(big2 == big);
    GuestFree(big2);

    GuestFree(b);
    GuestFree(reused);
    GuestFree(aligned);
    LOGI("HeapSelfCheck %s", ok ? "OK" : "FAILED");
#undef TT_CHECK
}

void DynarmicHost::GuestFree(uint32_t addr) {
    if (addr < kHeapBase + kHeaderSize) return;         // cannot be one of ours
    if (MemoryRead32(addr - 16) != kBlockMagic) return; // foreign pointer, or already freed
    uint32_t base = MemoryRead32(addr - 12);
    uint32_t capacity = MemoryRead32(addr - 8);
    MemoryWrite32(addr - 16, kFreedMagic);

    std::lock_guard<std::mutex> lk(m_heap_mutex);
    if (capacity <= kMaxClassSize) {
        int cls = 0;
        while ((1u << (cls + kMinClassShift)) < capacity) ++cls;
        m_free_small[cls].push_back(base);
    } else {
        m_free_huge[capacity].push_back(base);
    }
}

uint32_t DynarmicHost::AllocGuestStack(size_t size) {
    uint32_t base = GuestAlloc(size, 0x10000);
    return base + static_cast<uint32_t>(size) - 8; // stack top
}

std::optional<std::uint32_t> DynarmicHost::MemoryReadCode(std::uint32_t vaddr) {
    // Runaway PC containment. Only the trap/trampoline page and the two loaded
    // modules hold code; everything else in the arena is zero-filled heap, and
    // zeros decode as andeq r0,r0,r0 — so a bad jump makes the JIT translate a
    // fresh block every 0x8000 bytes forever until the LMK kills us. Feed it a
    // permanently-undefined instruction instead: ExceptionRaised halts the JIT
    // and prints where the jump came from.
    if (!((vaddr < 0x00020000u) ||
          (vaddr >= 0x40000000u && vaddr < 0x40A00000u))) {
        LOGE("[RUNAWAY] code fetch 0x%08X", vaddr);
        return 0xE7FEDEFFu; // permanently undefined
    }
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) {
        return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    }
    return std::nullopt;
}

std::uint8_t DynarmicHost::MemoryRead8(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) return m_memory[vaddr];
    return 0;
}

std::uint16_t DynarmicHost::MemoryRead16(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) return *reinterpret_cast<uint16_t*>(m_memory + vaddr);
    return 0;
}

std::uint32_t DynarmicHost::MemoryRead32(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    return 0;
}

std::uint64_t DynarmicHost::MemoryRead64(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) return *reinterpret_cast<uint64_t*>(m_memory + vaddr);
    return 0;
}

void DynarmicHost::MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) m_memory[vaddr] = value;
}

void DynarmicHost::MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) *reinterpret_cast<uint16_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) {
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) *reinterpret_cast<uint32_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) *reinterpret_cast<uint64_t*>(m_memory + vaddr) = value;
}

// STREX: compare-and-set against guest memory. The ExclusiveMonitor already holds its lock
// around this and has verified the reservation, so a plain compare/store is sufficient.
template<typename T>
static bool GuestCompareAndSwap(uint8_t* mem, size_t mem_size, uint32_t vaddr, T value, T expected) {
    if (static_cast<uint64_t>(vaddr) + sizeof(T) > mem_size) return false;
    T* p = reinterpret_cast<T*>(mem + vaddr);
    if (*p != expected) return false;
    *p = value;
    return true;
}

bool DynarmicHost::MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

void DynarmicHost::InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) {
    LOGE("Interpreter Fallback at 0x%08X", pc);
    if (t_running_jit) t_running_jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::CallSVC(std::uint32_t swi) {
    if (!t_running_jit) return;
    if (swi == 0) {
        // Exit trap: halt the instance that is actually executing on this host
        // thread (per-thread Jits mean there is no single "the" Jit).
        t_running_jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
        return;
    }
    m_thunk_manager->DispatchThunk(swi, *t_running_jit);
}

void DynarmicHost::ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) {
    LOGE("Exception at PC: 0x%08X (type %d)", pc, static_cast<int>(exception));
    if (t_running_jit) {
        const auto& r = t_running_jit->Regs();
        LOGE("  r0-r7 %08X %08X %08X %08X %08X %08X %08X %08X sp=%08X lr=%08X",
             r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[13], r[14]);
        t_running_jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
    }
}

void DynarmicHost::AddTicks(std::uint64_t ticks) {
    if (m_ticks_remaining > ticks) m_ticks_remaining -= ticks;
    else m_ticks_remaining = 0;
}

std::uint64_t DynarmicHost::GetTicksRemaining() {
    return m_ticks_remaining;
}

extern std::vector<uint8_t> HostReadAsset(const char* name);

void DynarmicHost::Thunk_GFxFileOpener_OpenFile(Dynarmic::A32::Jit& jit, DynarmicHost& host) {
    uint32_t url_gaddr = jit.Regs()[1];
    const char* url = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + url_gaddr);

    // Anything that is not an APK asset (save files, shader cache, ...) goes to
    // the guest's own opener, which supports writing.
    if (!url_gaddr || strncmp(url, "assets://", 9) != 0) {
        jit.Regs()[12] = 1;
        return;
    }
    jit.Regs()[12] = 0;

    const char* asset_name = url + 9;
    std::vector<uint8_t> data = HostReadAsset(asset_name);
    if (data.empty()) {
        LOGE("[Scaleform] OpenFile: asset '%s' not found", asset_name);
        jit.Regs()[0] = 0;
        return;
    }

    // The arena is a bump allocator and nothing below is ever freed, so the
    // payload and its URL node are cached per asset: the game re-opens the same
    // SWFs on every level load and without this the leak was hundreds of MB per
    // session. Only the small MemoryFile wrapper (which carries the read
    // position) is per-open.
    struct CachedAsset { uint32_t buf, len, gstr; };
    static std::mutex s_cache_mtx;
    static std::unordered_map<std::string, CachedAsset> s_cache;

    uint32_t data_len = static_cast<uint32_t>(data.size());
    uint32_t g_buf = 0, gstr_node = 0;
    {
        std::lock_guard<std::mutex> lk(s_cache_mtx);
        auto it = s_cache.find(url);
        if (it != s_cache.end() && it->second.len == data_len) {
            g_buf = it->second.buf;
            gstr_node = it->second.gstr;
        } else {
            g_buf = host.GuestAlloc(std::max(data_len, 64u), 8);
            memcpy(host.GetGuestMemoryBase() + g_buf, data.data(), data_len);

            // Scaleform GString node (GString::DataDesc)
            size_t url_len = strlen(url);
            gstr_node = host.GuestAlloc(url_len + 16, 8);
            host.MemoryWrite32(gstr_node + 0, static_cast<uint32_t>(url_len)); // length
            host.MemoryWrite32(gstr_node + 4, 1000);                           // refcount
            memcpy(host.GetGuestMemoryBase() + gstr_node + 8, url, url_len + 1);

            s_cache[url] = {g_buf, data_len, gstr_node};
        }
    }

    // Scaleform MemoryFile object (256 bytes covers all subclass fields up to 0x58+).
    uint32_t g_memfile = host.GuestAlloc(256, 8);
    memset(host.GetGuestMemoryBase() + g_memfile, 0, 256);
    host.MemoryWrite32(g_memfile + 0, 0x405FE710); // vtable off_5FE710
    // Every block here comes from the bump allocator, NOT from Scaleform's heap,
    // so nothing must ever reach GMemory::Free: unlinking a foreign pointer from
    // its red-black free tree corrupts the tree, and the next allocation either
    // walks a cycle (RSS runs away until the LMK kills us) or dereferences a node
    // at -8. Pin the refcount and leave pBuffer null so the destructor never runs;
    // the arena is never reclaimed anyway.
    host.MemoryWrite32(g_memfile + 4, 0x40000000);  // refcount: never released
    host.MemoryWrite32(g_memfile + 8, gstr_node);   // GString::DataDesc*
    host.MemoryWrite32(g_memfile + 12, g_buf);      // pData
    host.MemoryWrite32(g_memfile + 16, data_len);   // fileSize
    host.MemoryWrite32(g_memfile + 20, 0);          // filePos = 0
    host.MemoryWrite8(g_memfile + 24, 1);           // open = true
    host.MemoryWrite32(g_memfile + 28, 0);          // pBuffer: not ours to free

    jit.Regs()[0] = g_memfile;
}
