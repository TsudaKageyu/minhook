# SAFE-FREEZE candidate design

The owner authorized BSD-2-Clause licensing of their SAFE-FREEZE contributions
on 2026-11-10. Preserve all original notices and the separate contribution
license. Native verification and upstream acceptance remain independent gates.
See SAFE_FREEZE_LICENSE_NOTICE.md.

## Selection and compatibility

`MINHOOK_SAFE_FREEZE=OFF` retains the original engine's C tokens after selecting
the strict conditional, including both architecture/debug branches. `ON`
enables the complete strict engine, not a reduced subset.
The public header, export definitions, C entry points and status enum are
unchanged. The option does not change the shipping project's vendor tree.

Default-on strict behavior would change upstream best-effort semantics:
unreadable live peer contexts now prevent patching; missing NtGetNextThread
does not fall back to Toolhelp; failed physical cleanup remains owned and
blocks later unsafe mutations. Keep the upstream default and require explicit
build-time selection until upstream maintainers approve a different default.
This is a compatibility design proposal, not permission to weaken strict mode.

## Complete strict engine

Enumeration requests suspend, query, get-context and set-context rights. Every
returned cursor is closed or retained; every peer duplicate is owned. The
current thread is excluded. Enumeration, allocation and deferred cleanup have
distinct existing status mappings. Both emergency slots preserve coincident
cursor/duplicate release failures. No third-party enumeration code is imported.

A suspended owner tracks only the suspension added by this engine. Live
unresolved suspend/context failures prevent code patching. Terminated/invalid
peers can retire their ownership. Failed resume, close or backing-array release
keeps the owner reachable for a later retry. Uninitialization retains its heap
while peer ownership remains unresolved. Single disable, queued and all-hook
operations use the appropriate target/trampoline IP relocation direction.

The port adds a common retry guard before public mutation paths, including an
empty ApplyQueued and already-disabled RemoveHook. Previously those two paths
could report success or retire a trampoline without trying retained cleanup.
Regression tests fail when either guard is individually removed.

## Patch completion and generated-code retirement

The strict engine also records per-page protection restoration and cache
completion. It preserves the physical enabled state after a write, even when a
later API fails, and blocks further mutations until completion succeeds. Peers
owned by that incomplete operation stay suspended until completion/release can
be retried. Persistent OS failures can therefore stall peers and leave shutdown
pending; this design does not promise availability under unrecoverable failures.
Generated trampoline/relay code is flushed before publishing its pointer.

Before recycling a slot or releasing all generated-code blocks, strict mode
freezes peers and checks their instruction/integer registers and bounded stack
words against the retiring ranges. This accounts for a peer redirected into a
trampoline before a later preparation or target-write failure, and for generated
code addresses on the stack while its instruction pointer is elsewhere. x86
uses EIP/ESP and pointer-sized words; x64 uses RIP/RSP and pointer-sized words.
Read, short-read, query, preparation and context failures defer retirement.

Failed VirtualFree keeps the exact block/slot linked and unrecycled. Partial
block release enters a shutdown-only state, so stale entries cannot be enabled
while remaining blocks/heap are still owned. HeapDestroy is checked after peer
array cleanup; failure keeps its handle and the same cleanup owner for retry.
Per-page protection records cover ordinary and patch-above ranges crossing
pages with different original protections.

These changes are selected only by MH_SAFE_FREEZE. The default source-token
check covers hook.c, buffer.c and buffer.h against the immutable official base,
including both architecture branches. It does not claim identical PE bytes or
that upstream's legacy error behavior is free of defects.

The standalone completion fixture injects OS-boundary failures with projected
peer contexts and real target-page protection. It never executes its target or
trampoline bytes. The separate retirement fixture manipulates and restores a
genuine externally suspended Windows peer's context/stack and checks foreign
suspension counts. These evidence classes remain distinct from actual leaf-call
and churn tests. A successful fixture does not establish arbitrary host safety.

## Limits requiring review

NtGetNextThread is undocumented and does not create a process-wide atomic
snapshot. A newly born thread can run after enumeration; open upstream PR #151
addresses thread-creation behavior separately. This candidate does not merge
that unaccepted dependency or claim to close the race.

MinHook still patches multiple hooks sequentially. A later VirtualProtect
failure can leave earlier hooks transitioned. Context relocation itself is not
a transactional multi-peer journal. SAFE-FREEZE ownership retention is not a
proof of all-or-nothing code/context publication. Callers must inspect failures,
stop future trampoline use and establish application-level quiescence before
retirement. Conservative range checks may defer cleanup for stale pointer
values; they are not a universal thread-birth or arbitrary host-stack proof.
Target code must remain mapped and must not be concurrently patched by a
different owner. The original application transaction and
callback-drain protocol are deliberately not imported into this library.

Do not initialize or perform freeze/patch/teardown under loader lock. This
engine does not add DllMain management or enforce application startup ordering.
No API/status expansion or process-wide hooks are introduced.

Native Windows/MSVC x64/x86 Debug/Release tests, stress and performance remain
separate gates. Wine and injected peers do not prove native Windows acceptance.
Externally suspended real-peer fixtures exercise owned thread contexts; fixture
instruction bytes are never executed and arbitrary live target-call retirement
is outside that fixture's evidence.

The separate live-caller regression executes real leaf functions through both
the patched target and the original trampoline, including Win32 WINAPI stack
cleanup and x64 argument passing. It checks direct/queued transitions under
active calls, then joins the caller before removal or uninitialization. This
proves the owned fixture's calling behavior, not arbitrary application unload
or deep-stack return-address rewriting. No application call-gate is imported.

## Current native verification

[Native run 43374271934](https://github.com/cyanoleon/minhook/actions/runs/43374271934)
passed MSVC Win32/x64 Debug/Release and installed clang-cl x64 Release. Its
[source manifest at 2557e10](https://github.com/cyanoleon/minhook/blob/2557e10c163e9e2b4e3cfc9070ce97b73da88d8d/SOURCE_MANIFEST.json)
pins the compiled contribution inputs to code revision
`a29eaa2aaa6e7eb8e4875c239d9ca861130d4b2a`. This section is a documentation-only
addition; the validated compiled inputs are unchanged.

The five cells recorded 335 successful positive child-process executions,
15 precise expected-failure controls and 25 passing standalone CTest entries,
with no skipped standalone entries. Positive totals include repeated injected
fault regressions, stress and comparative workloads, not 335 unique defects.
The completion fixture ran 263 checks per Win32 cell and 199 per x64 cell;
each cell also ran 27 genuine suspended-peer retirement checks. Injected peers,
actual context/stack manipulation and live target execution remain distinct.

Strict-ON and default-OFF actual shared DLLs were built in every cell. Ten PE32
or PE32+ export checks verified the original 12 named function exports. Downloaded
contribution sources, executable identities, JUnit results and strict/default
DLL identities were checked against the recorded hashes. The three-file
strict-OFF source-token comparison also passed against the official base.

The linked run retains fresh Release comparisons with 1/4/16/32/64 owned workers,
1/4/11 hooks, five warm-ups and 200 samples per workload; clang-cl stress uses
50 samples. Nine operations and bounded resource observations are recorded.
The additional retirement checks perform extra teardown work. Different context
relocation/original-pointer contracts and unsafe-none are not safety-equivalent,
and timings do not establish universal superiority or continuous high-water
resource bounds. Results from earlier candidate revisions are historical.

The [current benchmark tables](BENCHMARK_RESULTS.md) give fresh Win32/x64
queued-enable and engine-retirement quantiles, plus all nine previous/current
strict x64 operation medians and p95 values. They explicitly separate the added
retirement cost from intercepted-call latency and identify the run/revision
behind each measurement.
