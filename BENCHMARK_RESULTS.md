# Current benchmark measurements

These are measured results, not a universal engine speed or safety ranking.
The tested code revision is `a29eaa2aaa6e7eb8e4875c239d9ca861130d4b2a`.
The benchmark report is documentation only; the compiled inputs remain unchanged.

- Current native run: [43374271934](https://github.com/cyanoleon/minhook/actions/runs/43374271934).
- Validation source manifest: [2557e10](https://github.com/cyanoleon/minhook/blob/2557e10c163e9e2b4e3cfc9070ce97b73da88d8d/SOURCE_MANIFEST.json).
- Official input: `8af6b4acae5a9388fd742b56fa79ece89d96f823`.
- Comparison input: `m417z/minhook` at `4f18d1809a81e6c700bcc4a21aeb43ade72bbf8b`; this is not MinHook-Detours.

## Workload and measurement scope

The example below is Release, 64 owned workers and 11 hooks, with five warm-ups
and 200 timed samples per implementation/mode. Values are microseconds (`us`).
Both current MSVC Release cells reported AMD EPYC 7763, four logical processors,
MSVC 19.44 and Windows kernel 10.0.20348. They are separate CI jobs, not a paired
cross-architecture hardware experiment. The 64-worker example oversubscribes
those four logical processors; it is not a prediction for every host process.

The timed workers wait on an event; the benchmark does not execute the target
or trampoline bytes. Separate live-caller tests check functional calling
behavior. These measurements cover nine lifecycle operations, not call-through
latency, FPS or application callback-drain/DLL-unload wall time. The full raw
run also covers 1/4/16/32/64 workers and 1/4/11 hooks.

## Current queued enable

| Architecture | Implementation / mode | Median (us) | p95 (us) | p99 (us) |
| --- | --- | ---: | ---: | ---: |
| Win32 | Official upstream | 10985.85 | 14154.70 | 15304.70 |
| Win32 | Candidate, strict OFF | 10731.10 | 11542.90 | 12421.60 |
| Win32 | Brownfield SAFE-FREEZE, strict ON | 2766.10 | 3237.10 | 3350.70 |
| Win32 | m417z MinHook, original | 29091.45 | 35072.10 | 35418.90 |
| Win32 | m417z MinHook, fast-undocumented | 23034.75 | 25411.40 | 29769.60 |
| Win32 | m417z MinHook, unsafe-none | 34.40 | 34.70 | 39.90 |
| x64 | Official upstream | 9928.60 | 10554.40 | 10720.60 |
| x64 | Candidate, strict OFF | 9088.85 | 9643.30 | 9854.00 |
| x64 | Brownfield SAFE-FREEZE, strict ON | 2465.95 | 2564.60 | 3065.80 |
| x64 | m417z MinHook, original | 24988.10 | 31112.30 | 31557.70 |
| x64 | m417z MinHook, fast-undocumented | 20225.65 | 20614.00 | 21226.40 |
| x64 | m417z MinHook, unsafe-none | 29.30 | 29.50 | 30.60 |

## Current engine retirement

All hooks have already been disabled when the timer around `MH_Uninitialize`
starts. Strict mode now freezes peers and checks integer/control registers and
stack words before releasing generated code. The other modes do not perform
equivalent generated-code retirement checks. The cost difference is intentional
additional work and must not be presented as an equivalent-safety comparison.

| Architecture | Implementation / mode | Median (us) | p95 (us) | p99 (us) |
| --- | --- | ---: | ---: | ---: |
| Win32 | Official upstream | 20.85 | 29.00 | 35.30 |
| Win32 | Candidate, strict OFF | 19.60 | 28.40 | 37.50 |
| Win32 | Brownfield SAFE-FREEZE, strict ON | 3115.70 | 3483.50 | 3679.90 |
| Win32 | m417z MinHook, original | 20.15 | 25.10 | 30.30 |
| Win32 | m417z MinHook, fast-undocumented | 34.45 | 40.60 | 42.60 |
| Win32 | m417z MinHook, unsafe-none | 6.20 | 7.90 | 9.80 |
| x64 | Official upstream | 11.30 | 19.60 | 20.60 |
| x64 | Candidate, strict OFF | 10.95 | 18.90 | 23.10 |
| x64 | Brownfield SAFE-FREEZE, strict ON | 2890.50 | 3001.60 | 3325.70 |
| x64 | m417z MinHook, original | 14.35 | 17.70 | 20.50 |
| x64 | m417z MinHook, fast-undocumented | 17.90 | 24.80 | 37.80 |
| x64 | m417z MinHook, unsafe-none | 6.20 | 6.60 | 6.80 |

## Previous versus current strict x64 result

The previous run is [42854184081](https://github.com/cyanoleon/minhook/actions/runs/42854184081),
code revision `9c4753f771b437898025bd75912f2ac1f063cd07`. This compares the same
64-worker/11-hook Release workload with 200 samples and five warm-ups. Both
runs report the same CPU model, logical-processor count, compiler and OS kernel;
they remain different CI sessions without paired or randomized old/new runs.

| Operation | Previous median (us) | Current median (us) | Previous p95 (us) | Current p95 (us) |
| --- | ---: | ---: | ---: | ---: |
| Initialize | 12.80 | 13.10 | 20.30 | 19.80 |
| Create 11 hooks | 28.30 | 28.00 | 34.20 | 33.80 |
| Single enable | 2482.70 | 2445.30 | 3004.10 | 2526.10 |
| Single disable | 2480.60 | 2434.65 | 3019.70 | 2522.30 |
| Queued enable | 2501.50 | 2465.95 | 3024.20 | 2564.60 |
| Queued disable | 2502.40 | 2465.95 | 3015.70 | 2562.90 |
| Direct freeze | 1758.50 | 1701.20 | 2289.70 | 1799.10 |
| Direct unfreeze | 717.40 | 734.95 | 741.70 | 755.60 |
| Uninitialize | 12.90 | 2890.50 | 21.10 | 3001.60 |

The observed uninitialize median increases from 12.90 us to 2890.50 us, an
additional 2877.60 us (about 2.88 ms) in this workload. This is engine-retirement
cost, not overhead on every intercepted call. The patch/activation medians are
close across these two runs; their small differences are not evidence of a
causal speed improvement.

## Interpretation limits

- Official and candidate strict-OFF have the same engine C tokens. Differences
  between their separately executed measurements are not a new OFF algorithm
  or a demonstrated optimization.
- The comparison fork has different multihook/original-pointer semantics and
  does not perform equivalent context relocation in its direct freeze path.
  Unsafe-none deliberately omits freezing and IP relocation. Its low timings
  are not a safety-equivalent alternative.
- Quantiles are within-workload observations, not confidence intervals for a
  version-to-version effect. Current strict retirement performs more work than
  the previous implementation and the comparison modes.
- The selected rows report zero residual handles. Memory/handle peaks are
  bounded observations, not continuous high-water guarantees. Historical run
  values must not be relabelled as measurements of the current code.
