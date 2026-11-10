# Private candidate design

The owner authorized BSD-2-Clause licensing of their SAFE-FREEZE contributions
on 2026-11-10. Preserve all original notices and the separate contribution
license. Native verification and upstream acceptance remain independent gates.
See SAFE_FREEZE_LICENSE_NOTICE.md.

## Selection and compatibility

`MINHOOK_SAFE_FREEZE=OFF` retains the exact original engine source after
preprocessing. `ON` enables the complete strict engine, not a reduced subset.
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

## Limits requiring review

NtGetNextThread is undocumented and does not create a process-wide atomic
snapshot. A newly born thread can run after enumeration; open upstream PR #151
addresses thread-creation behavior separately. This candidate does not merge
that unaccepted dependency or claim to close the race.

MinHook still patches multiple hooks sequentially. A later VirtualProtect
failure can leave earlier hooks transitioned. Context relocation itself is not
a transactional multi-peer journal. SAFE-FREEZE ownership retention is not a
proof of all-or-nothing code/context publication. Callers must inspect failures
and preserve trampoline lifetime. The original application transaction and
callback-drain protocol are deliberately not imported into this library.

Do not initialize or perform freeze/patch/teardown under loader lock. This
engine does not add DllMain management or enforce application startup ordering.
No API/status expansion or process-wide hooks are introduced.

Native Windows/MSVC x64/x86 Debug/Release tests, stress and performance remain
separate gates. Wine and injected peers do not prove native Windows acceptance.
Externally suspended real-peer fixtures exercise owned thread contexts; fixture
instruction bytes are never executed and arbitrary live target-call retirement
is outside that fixture's evidence.
