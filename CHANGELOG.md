## 1.0.0

- Initial stable release of `package:fuzz`:
  - Non-destructive `.dart_tool/fuzz/` AST overlay instrumentor
    (`fuzz instrument` and `fuzz run`) with incremental `overlay_cache.json`
    caching (`--force-instrument` to bypass), zero-dependency synchronous and
    in-memory `async` `FuzzTarget` (`FutureOr<void> Function(Uint8List)`)
    entrypoint synthesis (`fuzz_entrypoint.dart`), `--instrument-packages`
    support for delegated parser dependencies, `--work-dir` isolation for
    parallel runs, and target-scoped AST dictionary token extraction
    (`auto.dict`, `--dict`, `--[no-]auto-dict`).
  - Coverage-guided `libFuzzer` + `dart:ffi` runtime (`--mode=cgf`, default)
    with 8-bit edge counters, 512-slot `TraceCmp8WithPc` value-profile
    trampolines, `TraceMemcmp` byte-loop coalescing, and in-process
    `--[no-]keep-going` multi-crash deduplication, shortest-input minimization,
    and `crashes_report.json` / `.dart_tool/fuzz/crashes/crash-*` reproducer
    persistence (`-artifact_prefix` / `-exact_artifact_path`).
  - Pure-Dart evolutionary coverage- and comparison-guided fallback engine
    (`--mode=pure-dart`) with `-seed` control, `-dict` token mutation, corpus
    directory persistence, 64-bit word coverage scanning, and `libFuzzer`-style
    progress output.
  - Target-scoped per-file and per-line AST coverage reporting
    (`coverage_report.json` with `uncoveredLines` and
    `omittedUnreachableFiles`).
  - Reusable parser fuzzing combinators (`FuzzTarget`, `StreamContractResult`,
    `verifyChunkSplitEquivalence`, `captureStreamZoneErrors`,
    `verifyNoUnescapedCrlf`, `fuzzBoundaryInts`, `fuzzBoundaryHexStrings`).
