// SPDX-License-Identifier: BSD-2-Clause

// Link the real verified engine. No thread/context API is intercepted here.
// A real worker stays externally suspended during each mapping observation.
// Restore its original context before resuming; fixture code is never executed.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <MinHook.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#if defined(_M_X64) || defined(__x86_64__)
#define CONTEXT_IP(c) ((c).Rip)
#define EXPANDED_CALL_OFFSET 16
#else
#define CONTEXT_IP(c) ((c).Eip)
#define EXPANDED_CALL_OFFSET 5
#endif

namespace {
unsigned checks = 0, transitions = 0;
void check(bool ok, const char* message) {
    ++checks;
    if (!ok) throw std::runtime_error(message);
}
void status(MH_STATUS value, const char* message) { check(value == MH_OK, message); }
struct StaleSingleDisable {};
struct Hook {
    unsigned char* target = nullptr;
    unsigned char* trampoline = nullptr;
    unsigned char* detour = nullptr;
    bool above = false, created = false, enabled = false;
    std::array<unsigned char, 7> original{};
    unsigned char* patch() const { return target - (above ? 5 : 0); }
    std::size_t patch_size() const { return above ? 7 : 5; }
};
struct Mapping { unsigned hook, old_offset, new_offset; };
constexpr std::array<Mapping, 13> mappings{{
    {0,0,0},{0,1,1},{0,2,2},{0,3,3},{0,4,4},
    {1,0,0},{1,1,1},{1,2,2},{1,3,3},{1,4,4},
    {2,0,0}, // RET with a two-byte hotpatch entry and five-byte prelude.
    {3,0,0},{3,5,EXPANDED_CALL_OFFSET} // rel32 CALL expands to a 16-byte absolute CALL.
}};

class Fixture {
    HANDLE ready_ = nullptr, stop_ = nullptr, worker_ = nullptr;
    CONTEXT original_context_{};
    bool held_ = false, context_saved_ = false, engine_ = false;
    bool baseline_saved_ = false;
    DWORD baseline_ = 0, held_handles_ = 0;
    unsigned char* arena_ = nullptr;
    std::array<Hook, 4> hooks_{};

    static DWORD WINAPI worker(void* parameter) {
        auto& self = *static_cast<Fixture*>(parameter);
        if (!SetEvent(self.ready_)) return 2;
        return WaitForSingleObject(self.stop_, INFINITE) == WAIT_OBJECT_0 ? 0x53 : 3;
    }
    static DWORD handle_count() {
        DWORD count = 0;
        check(GetProcessHandleCount(GetCurrentProcess(), &count) != FALSE,
              "GetProcessHandleCount failed");
        return count;
    }
    void create(Hook& hook) {
        void* original = nullptr;
        status(MH_CreateHook(hook.target, hook.detour, &original), "create real fixture hook");
        hook.trampoline = static_cast<unsigned char*>(original);
        hook.created = true;
        check(original != nullptr, "real trampoline missing");
    }
    void seed(unsigned char* ip) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        check(GetThreadContext(worker_, &context) != FALSE, "read real suspended worker context");
        CONTEXT_IP(context) = reinterpret_cast<DWORD_PTR>(ip);
        check(SetThreadContext(worker_, &context) != FALSE, "position real suspended worker IP");
    }
    unsigned char* ip() {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        check(GetThreadContext(worker_, &context) != FALSE, "read real post-operation context");
        return reinterpret_cast<unsigned char*>(CONTEXT_IP(context));
    }
    void balanced() {
        // The engine may add/remove its own suspension, but must leave ours.
        const DWORD before = SuspendThread(worker_);
        check(before != static_cast<DWORD>(-1), "probe real worker suspension count");
        if (before == 0) {
            // Retain this new suspension for safe context restoration on failure.
            throw std::runtime_error("engine over-resumed the externally held worker");
        }
        const DWORD released = ResumeThread(worker_);
        check(released == before + 1 && before == 1, "engine leaked a real suspension");
        check(handle_count() == held_handles_, "engine leaked a real thread/cursor handle");
        ++transitions;
    }
    void bytes() {
        for (const auto& hook : hooks_) {
            if (!hook.created || !hook.enabled) {
                check(std::memcmp(hook.patch(), hook.original.data(), hook.patch_size()) == 0,
                      "disabled or removed target bytes not restored");
            } else {
                check(hook.patch()[0] == 0xe9, "enabled target lacks its real rel32 patch");
                if (hook.above) check(hook.target[0] == 0xeb, "hotpatch entry lacks short jump");
            }
        }
    }
    void all_enabled(bool enabled) { for (auto& hook : hooks_) hook.enabled = enabled; }
    void observe(unsigned char* expected) {
        balanced();
        check(ip() == expected, "real worker instruction-pointer mapping differs");
        bytes();
    }
    void disable_single(Hook& hook, unsigned char* expected, unsigned char* previous) {
        status(MH_DisableHook(hook.target), "single disable with a real suspended peer");
        hook.enabled = false;
        balanced();
        const auto actual = ip();
        bytes();
        if (actual != expected && actual == previous) throw StaleSingleDisable{};
        check(actual == expected, "single disable returned an unexpected physical IP");
    }
public:
    Fixture() = default;
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    void open() {
        std::puts("REAL_PEER: owned Windows thread/context fixture starting");
        baseline_ = handle_count();
        baseline_saved_ = true;
        arena_ = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        check(arena_ != nullptr, "allocate owned executable fixture");
        std::memset(arena_, 0x90, 4096);
        const unsigned offsets[] = {0,64,128,256};
        const unsigned detours[] = {32,96,160,304};
        for (unsigned n = 0; n < hooks_.size(); ++n) {
            auto& hook = hooks_[n];
            hook.target = arena_ + offsets[n];
            hook.detour = arena_ + detours[n];
            hook.target[16] = 0xc3;
            hook.detour[0] = 0xc3;
        }
        auto& hot = hooks_[2];
        hot.above = true;
        hot.target[0] = 0xc3; hot.target[1] = 0x90;
        hot.target[2] = 0x41; hot.target[3] = 0x42; hot.target[4] = 0x43;
        auto& call = hooks_[3];
        call.target[0] = 0xe8;
        const std::int32_t displacement = 32 - 5;
        std::memcpy(call.target + 1, &displacement, sizeof displacement);
        call.target[32] = 0xc3;
        check(FlushInstructionCache(GetCurrentProcess(), arena_, 4096) != FALSE,
              "flush owned fixture instructions");
        status(MH_Initialize(), "initialize actual patched engine"); engine_ = true;
        for (auto& hook : hooks_) {
            std::memcpy(hook.original.data(), hook.patch(), hook.patch_size());
            create(hook);
        }
        check(call.trampoline[0] == 0xff && call.trampoline[1] == 0x15 &&
              call.trampoline[16] == 0xff && call.trampoline[17] == 0x25,
              "expected CALL expansion/jump-back boundaries differ");
        check(hot.trampoline[0] == 0xc3, "expected hotpatch trampoline differs");
        ready_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        check(ready_ && stop_, "create owned worker events");
        worker_ = CreateThread(nullptr, 0, worker, this, 0, nullptr);
        check(worker_ != nullptr, "create real fixture worker");
        check(WaitForSingleObject(ready_, 5000) == WAIT_OBJECT_0, "worker startup handshake");
        const DWORD before = SuspendThread(worker_);
        check(before != static_cast<DWORD>(-1), "externally suspend real worker");
        held_ = true;
        check(before == 0, "worker was unexpectedly suspended before the fixture");
        original_context_.ContextFlags = CONTEXT_FULL;
        check(GetThreadContext(worker_, &original_context_) != FALSE, "save original real context");
        context_saved_ = true;
        held_handles_ = handle_count();
    }
    void run() {
        for (const auto point : mappings) {
            auto& hook = hooks_[point.hook];
            auto* target = hook.target + point.old_offset;
            auto* trampoline = hook.trampoline + point.new_offset;
            seed(target);
            status(MH_EnableHook(hook.target), "single enable with a real peer");
            hook.enabled = true;
            observe(trampoline);
            disable_single(hook, target, trampoline);
        }
        std::puts("REAL_PEER: single enable/disable mapped 13 instruction boundaries");
        for (const auto point : mappings) {
            auto& hook = hooks_[point.hook];
            auto* target = hook.target + point.old_offset;
            auto* trampoline = hook.trampoline + point.new_offset;
            seed(target);
            for (auto& item : hooks_) status(MH_QueueEnableHook(item.target), "queue real hook enable");
            status(MH_ApplyQueued(), "apply queued enable with real peer"); all_enabled(true);
            observe(trampoline);
            status(MH_QueueDisableHook(hook.target), "queue single hook disable");
            status(MH_ApplyQueued(), "apply queued single disable"); hook.enabled = false;
            observe(target);
            status(MH_DisableHook(MH_ALL_HOOKS), "reset remaining queued hooks"); all_enabled(false);
            observe(target);
            status(MH_QueueEnableHook(MH_ALL_HOOKS), "queue all enable");
            status(MH_ApplyQueued(), "apply queued all enable"); all_enabled(true);
            observe(trampoline);
            status(MH_QueueDisableHook(MH_ALL_HOOKS), "queue all disable");
            status(MH_ApplyQueued(), "apply queued all disable"); all_enabled(false);
            observe(target);
            status(MH_EnableHook(MH_ALL_HOOKS), "direct all-hook enable"); all_enabled(true);
            observe(trampoline);
            status(MH_DisableHook(MH_ALL_HOOKS), "direct all-hook disable"); all_enabled(false);
            observe(target);
        }
        std::puts("REAL_PEER: queued-single, queued-all and direct-all IP transitions passed");
#if defined(_M_X64) || defined(__x86_64__)
        for (auto& hook : hooks_) {
            seed(hook.target);
            status(MH_EnableHook(hook.target), "enable relay fixture"); hook.enabled = true;
            std::int32_t distance = 0;
            std::memcpy(&distance, hook.patch() + 1, sizeof distance);
            auto* relay = reinterpret_cast<unsigned char*>(
                reinterpret_cast<std::intptr_t>(hook.patch() + 5) + distance);
            check(relay[0] == 0xff && relay[1] == 0x25, "expected real x64 relay differs");
            seed(relay);
            disable_single(hook, hook.target, relay);
        }
#endif
        auto& hot = hooks_[2];
        seed(hot.target);
        status(MH_EnableHook(hot.target), "enable hotpatch-prelude fixture"); hot.enabled = true;
        seed(hot.target - 5);
        disable_single(hot, hot.target, hot.target - 5);
        std::puts("REAL_PEER: architecture-specific relay and hotpatch prelude mapped back to targets");
        for (const auto point : mappings) {
            auto& hook = hooks_[point.hook];
            seed(hook.target + point.old_offset);
            status(MH_EnableHook(hook.target), "enable hook before live removal"); hook.enabled = true;
            observe(hook.trampoline + point.new_offset);
            status(MH_RemoveHook(hook.target), "remove enabled hook with real trampoline IP");
            hook.created = hook.enabled = false;
            observe(hook.target + point.old_offset);
            check(MH_DisableHook(hook.target) == MH_ERROR_NOT_CREATED, "removed hook still registered");
            create(hook);
        }
        for (auto& hook : hooks_) {
            seed(hook.target);
            status(MH_RemoveHook(hook.target), "remove already disabled hook"); hook.created = false;
            observe(hook.target);
            create(hook);
        }
        std::puts("REAL_PEER: enabled and disabled RemoveHook retained correct physical IPs");
        seed(hooks_[3].target + 5);
        status(MH_EnableHook(MH_ALL_HOOKS), "enable all before uninitialize"); all_enabled(true);
        observe(hooks_[3].trampoline + EXPANDED_CALL_OFFSET);
        status(MH_Uninitialize(), "uninitialize with a real peer in an expanded trampoline");
        engine_ = false;
        for (auto& hook : hooks_) hook.created = hook.enabled = false;
        observe(hooks_[3].target + 5);
        check(MH_DisableHook(MH_ALL_HOOKS) == MH_ERROR_NOT_INITIALIZED, "engine ownership not retired");
    }
    bool cleanup() noexcept {
        // On failure retain unresolved resources until this owned child exits.
        if (held_ && context_saved_ && !SetThreadContext(worker_, &original_context_)) return false;
        if (engine_) {
            if (MH_Uninitialize() != MH_OK) return false;
            engine_ = false;
        }
        if (worker_) {
            if (!SetEvent(stop_)) return false;
            if (held_) {
                if (ResumeThread(worker_) != 1) return false;
                held_ = false;
            }
            if (WaitForSingleObject(worker_, 5000) != WAIT_OBJECT_0) return false;
            DWORD code = 0;
            if (!GetExitCodeThread(worker_, &code) || code != 0x53) return false;
            if (!CloseHandle(worker_)) return false;
            worker_ = nullptr;
        }
        if (ready_) { if (!CloseHandle(ready_)) return false; ready_ = nullptr; }
        if (stop_) { if (!CloseHandle(stop_)) return false; stop_ = nullptr; }
        if (arena_) { if (!VirtualFree(arena_, 0, MEM_RELEASE)) return false; arena_ = nullptr; }
        DWORD handles = 0;
        return !baseline_saved_ ||
            (GetProcessHandleCount(GetCurrentProcess(), &handles) && handles == baseline_);
    }
};
}
int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    Fixture fixture;
    int code = 1;
    try {
        fixture.open(); fixture.run(); code = 0;
    } catch (const StaleSingleDisable&) {
        std::fputs("SINGLE_DISABLE_IP_MISMATCH: real IP retained the trampoline/relay address\n", stderr);
        code = 42;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s (last Windows error %lu)\n", error.what(), GetLastError());
    }
    if (!fixture.cleanup()) {
        std::fputs("FAIL: real peer cleanup incomplete; unresolved owners retained until child exit\n", stderr);
        return 1;
    }
    std::puts("REAL_PEER_CLEANUP: PASS original context restored, worker joined, handle count restored");
    if (code == 0) std::printf("REAL_PEER: PASS checks=%u balanced-transitions=%u\n", checks, transitions);
    return code;
}
