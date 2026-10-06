## 0.1.0-wip

- Initial version of `package:fuzz`:
  - Non-destructive `.dart_tool/fuzz/` AST overlay instrumentor
    (`fuzz instrument` and `fuzz run`).
  - Coverage-guided `libFuzzer` + `dart:ffi` runtime (`--mode=cgf`, default)
    with 8-bit edge counters, 512-slot `TraceCmp8WithPc` value-profile
    trampolines, and `TraceMemcmp` byte-loop coalescing.
  - Pure-Dart evolutionary coverage- and comparison-guided fallback engine
    (`--mode=pure-dart`).
  - Per-file and per-line AST coverage reporting (`coverage_report.json` with
    `uncoveredLines`).
  - Reusable parser fuzzing combinators (`verifyChunkSplitEquivalence`,
    `captureStreamZoneErrors`, `verifyNoUnescapedCrlf`, `fuzzBoundaryInts`,
    `fuzzBoundaryHexStrings`).
