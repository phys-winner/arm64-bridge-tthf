// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/A32/config.h>
#include <dynarmic/interface/exclusive_monitor.h>

class ElfLoader;
class ThunkManager;

class DynarmicHost : public Dynarmic::A32::UserCallbacks {
public:
    // The full 32-bit guest address space. Mapping all of it means fastmem can resolve any
    // guest address as base + zext32(vaddr) without ever faulting.
    static constexpr size_t GUEST_ADDRESS_SPACE = 0x100000000ULL; // 4 GiB
    // Fallback if the 4 GiB reservation is refused: no fastmem, bounds-checked callbacks.
    static constexpr size_t GUEST_FALLBACK_SIZE = 0x80000000ULL;  // 2 GiB
    // Distinct exclusive-monitor slots. One per Jit, i.e. one per host thread that
    // ever runs guest code (main, GL, FMOD mixer, guest pthreads).
    static constexpr size_t MAX_GUEST_CORES = 64;

    DynarmicHost();
    ~DynarmicHost() override;

    bool Initialize();
    // Load the two guest libraries from memory buffers (APK assets).
    bool LoadGameMemory(const std::vector<uint8_t>& game_elf, const std::vector<uint8_t>& fmodex_elf);

    // The guest is SOFTFP: float/double arguments and results travel in the core
    // registers, so `args` is the complete argument list (r0..r3, then the stack).
    uint32_t RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args = {});
    // Run on a specific Jit instance + guest stack (used by guest threads).
    uint32_t RunFunctionOnJit(Dynarmic::A32::Jit& jit, uint32_t stack_top,
                              uint32_t target_pc, const std::vector<uint32_t>& args = {});
    // Call guest code from inside a thunk. Jit::Run is not reentrant, so this
    // spins up a throwaway Jit + stack; only for one-off setup calls.
    uint32_t RunFunctionNested(uint32_t target_pc, const std::vector<uint32_t>& args = {});

    // Per-host-thread Jit instance: the Java side drives the guest from the
    // main thread, the GL thread and the FMOD thread concurrently; each host
    // thread must run its own Jit (dynarmic forbids reentrant Run()).
    Dynarmic::A32::Jit& GetThreadJit();
    std::unique_ptr<Dynarmic::A32::Jit> CreateJitInstance();

    uint32_t AllocGuestStack(size_t size = 0x100000); // returns stack top addr

    uint8_t* GetGuestMemoryBase() const { return m_memory; }
    size_t GetGuestMemorySize() const { return m_memory_size; }
    ElfLoader& GetElfLoader() { return *m_elf_loader; }
    ElfLoader* GetFModExLoader() { return m_fmodex_loader.get(); }
    ThunkManager& GetThunkManager() { return *m_thunk_manager; }

    uint32_t GuestAlloc(size_t size, size_t alignment = 8);
    void GuestFree(uint32_t addr);
    // Payload size of a live GuestAlloc block, 0 if addr did not come from here.
    uint32_t GuestAllocSize(uint32_t addr);

    void Thunk_GFxFileOpener_OpenFile(Dynarmic::A32::Jit& jit, DynarmicHost& host);
    void PatchFmodDspBufferSize();

    // Dynarmic UserCallbacks interface
    std::optional<std::uint32_t> MemoryReadCode(std::uint32_t vaddr) override;

    std::uint8_t MemoryRead8(std::uint32_t vaddr) override;
    std::uint16_t MemoryRead16(std::uint32_t vaddr) override;
    std::uint32_t MemoryRead32(std::uint32_t vaddr) override;
    std::uint64_t MemoryRead64(std::uint32_t vaddr) override;

    void MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) override;
    void MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) override;
    void MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) override;
    void MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) override;

    // Needed now that global_monitor is set: the base-class defaults return false, which makes
    // every guest STREX report failure and spin its retry loop forever.
    bool MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) override;
    bool MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) override;
    bool MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) override;
    bool MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) override;

    void InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) override;
    void CallSVC(std::uint32_t swi) override;
    void ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) override;

    void AddTicks(std::uint64_t ticks) override;
    std::uint64_t GetTicksRemaining() override;

private:
    uint8_t* m_memory = nullptr;
    size_t m_memory_size = 0;
    bool m_fastmem = false;
    std::unique_ptr<Dynarmic::ExclusiveMonitor> m_monitor;
    std::unique_ptr<ElfLoader> m_elf_loader;
    std::unique_ptr<ElfLoader> m_fmodex_loader;
    std::unique_ptr<ThunkManager> m_thunk_manager;

    std::atomic<size_t> m_next_processor_id{0};

    // Guest heap: bump pointer for fresh memory, free lists for reuse.
    // Requests up to kMaxClassSize round to a power-of-two size class; anything
    // larger (asset payloads, thread stacks) is sized exactly and recycled by
    // exact capacity, so the repeated 8 MB stacks do not round up to 16 MB.
    static constexpr uint32_t kHeapBase = 0x50000000;
    static constexpr int kMinClassShift = 5;                          // 32 B smallest block
    static constexpr uint32_t kMaxClassSize = 1u << 20;               // 1 MB largest class
    static constexpr int kNumSizeClasses = 20 - kMinClassShift + 1;
    void HeapSelfCheck();
    std::mutex m_heap_mutex;
    std::vector<uint32_t> m_free_small[kNumSizeClasses];               // class -> block bases
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_free_huge;   // capacity -> block bases
    uint32_t m_heap_current = kHeapBase;                               // guarded by m_heap_mutex

    std::uint64_t m_ticks_remaining = 0;
};
