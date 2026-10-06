## 0.1.0-wip

- Initial version of `package:fuzz`:
  - Non-destructive `.dart_tool/fuzz/` AST overlay instrumentor
    (`fuzz instrument` and `fuzz run`) with `--instrument-packages` support for
    delegated parser dependencies, `--work-dir` isolation for parallel runs, and
    automatic AST dictionary token extraction (`auto.dict`, `--dict`,
    `--[no-]auto-dict`).
  - Coverage-guided `libFuzzer` + `dart:ffi` runtime (`--mode=cgf`, default)
    with 8-bit edge counters, 512-slot `TraceCmp8WithPc` value-profile
    trampolines, `TraceMemcmp` byte-loop coalescing, and automatic `crash-*`
    reproducer file persistence (`-artifact_prefix` / `-exact_artifact_path`).
  - Pure-Dart evolutionary coverage- and comparison-guided fallback engine
    (`--mode=pure-dart`) with `-seed` control, `-dict` token mutation, corpus
    directory persistence, 64-bit word coverage scanning, and `libFuzzer`-style
    progress output.
  - Per-file and per-line AST coverage reporting (`coverage_report.json` with
    `uncoveredLines`).
  - Reusable parser fuzzing combinators (`verifyChunkSplitEquivalence`,
    `captureStreamZoneErrors`, `verifyNoUnescapedCrlf`, `fuzzBoundaryInts`,
    `fuzzBoundaryHexStrings`).
