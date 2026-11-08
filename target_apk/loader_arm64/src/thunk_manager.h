// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <functional>
#include <array>
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

namespace Dynarmic::A32 {
    class Jit;
}

class DynarmicHost;

using ThunkHandler = std::function<void(Dynarmic::A32::Jit& jit, DynarmicHost& host)>;

class ThunkManager {
public:
    ThunkManager(DynarmicHost& host);
    ~ThunkManager();

    void RegisterAllThunks();
    // Returns the guest address of the trampoline for `name`.
    uint32_t RegisterThunk(const std::string& name, ThunkHandler handler);

    uint32_t GetOrCreateThunkAddress(const std::string& name);
    bool HasThunk(const std::string& name) const;
    void DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit);

private:
    void RegisterGLThunks();
    void RegisterLibcThunks();

    DynarmicHost& m_host;
    uint32_t m_next_thunk_addr = 0x00010000; // Base address for thunk trampolines
    std::unordered_map<std::string, uint32_t> m_symbol_to_address;
    static constexpr size_t kMaxThunks = (0x20000 - 0x10000) / 8;
    struct ThunkEntry { std::string name; ThunkHandler handler; };
    // A published entry remains alive even when the handler is replaced.
    std::array<std::atomic<const ThunkEntry*>, kMaxThunks> m_dispatch{};
    std::vector<std::unique_ptr<ThunkEntry>> m_entries;
    mutable std::mutex m_registry_mutex;
};
