---
name: codegen-fuzz
description: >-
  Stress-tests Dart source_gen, build, and analyzer code generators by
  extracting AST control-flow branch axes, generating combinatorial declaration
  matrices with cartesianProduct, and validating emitted code through
  verifyCodegenBatch across diagnostic contracts, analyzer static errors and
  warnings, and batched Isolate.spawnUri runtime round-trip execution. Use when
  fuzzing or stress-testing a Dart code generator, verifying generator changes
  across AST permutations, or running fuzz codegen. Do not use for byte-stream
  or text parser fuzzing with libFuzzer (use fuzz run).
---

# AST-Combinatorial Code Generator Fuzzing (`codegen-fuzz`)

Unlike byte-stream parsers, a Dart code generator (`source_gen`, `build`, or
`analyzer`-based builders such as `json_serializable`, `built_value`, `freezed`,
and `mockito`) takes **valid, resolved Dart declarations** (`ClassElement`,
`FieldElement`, `DartType`, `ConstantReader`) and emits Dart source code
(`.g.dart`). Uniform random bytes fail in the Dart parser before the generator
ever runs.

To fuzz a code generator effectively, permute the **AST declaration axes that
flip control-flow branches inside the generator** and validate every emitted
`.g.dart` part against three automated oracles in a single shared
`AnalysisContextCollection` and a single batched `Isolate.spawnUri` call via
`verifyCodegenBatch`.

## Quick Start (`fuzz codegen` Zero-Dependency Runner)

You do **not** need to modify the target package's `pubspec.yaml` or
`pubspec.lock`. Write a standalone script (for example in
`/tmp/fuzz_slice.dart`) that imports both `package:fuzz/fuzz.dart` and the
target generator, `cd` into the target package directory, and run
`fuzz codegen`:

```bash
cd /path/to/target_package && \
  dart run /path/to/fuzz.dart/bin/fuzz.dart codegen \
    --package-root=. \
    --work-dir=/tmp/fuzz_work \
    /tmp/fuzz_slice.dart
```

`fuzz codegen` synthesizes `codegen_package_config.json` (combining the target
package's dependencies with `package:fuzz`), forwards `--work-dir` via
`FUZZ_WORK_DIR` so temporary batch directories never dirty the target repo, and
executes your script with `--enable-asserts` in `< 50ms`.

## API Quick Reference (`package:fuzz/fuzz.dart`)

```dart
const CodegenCase({
  required String id,
  required String declarations,
  String? runtimeCheck,
  Pattern? expectedError,
});

Future<CodegenBatchReport> verifyCodegenBatch({
  required List<CodegenCase> cases,
  required CodegenPartGenerator generatePart,
  List<String> imports = const [],
  String preamble = '',
  Map<String, String> auxiliaryFiles = const {},
  String packageRoot = '.',
  String? workDir,
  bool includeWarnings = true,
  bool failOnIssues = true,
  Duration isolateTimeout = const Duration(seconds: 30),
});
```

## Workflow: How to Fuzz a Code Generator

### Phase 1: Map the Generator's AST Branch Axes

Before writing a fuzz script, read the target generator's `lib/src/` files and
list every condition that branches on the input `Element`, `DartType`, or
annotation `ConstantReader`:

1. **Type Nullability & Generic Bounds**:
   - Non-nullable `T` vs. nullable `T?` vs. `dynamic` / `Object?` / `Object`.
   - Unbounded `<T>` vs. bounded `<T extends Object>` or `<T extends num?>`.
   - `forceNullable` interactions (default values, nullable constructor
     parameters on non-nullable fields, custom converters).
2. **Container & Wrapper Nesting**:
   - Scalar `T`, `List<T>`, `Set<T>`, `Iterable<T>`, `Map<String, T>`,
     `Map<EnumKey, EnumVal>`, and nested `Map<String, List<T?>>`.
3. **Declaration Origin & Class Hierarchy**:
   - Regular fields, getter/setter pairs, virtual fields, `super.field`
     parameters, primary constructor declaring parameters, generic superclasses,
     mixins (`with M1, M2`), named mixin applications
     (`class Sub<T> = Base<T> with Mixin;`), and cross-library `typedef` aliases
     (`typedef Id<T> = T;`, `typedef NullableAlias = Foo?;`, private
     `typedef _Priv = String;` in an imported `auxiliaryFiles` library).
4. **Annotation & Configuration Combinations**:
   - Class-level and field-level flags that interact (`includeIfNull`,
     `explicitToJson`, `genericArgumentFactories`, `checked`,
     `disallowUnrecognizedKeys`, `createFieldMap`, `createPerFieldToJson`,
     custom `fromJson`/`toJson` tear-offs with optional/positional/generic
     parameters).

### Phase 2: Build the Combinatorial Matrix with `cartesianProduct`

Use `cartesianProduct` from `package:fuzz/fuzz.dart` to expand orthogonal axes
into `CodegenCase` entries. Group `100-500` cases per `verifyCodegenBatch` call
so the Dart SDK and package dependencies resolve once per batch (~1-2 seconds):

```dart
import 'dart:async';
import 'package:analyzer/dart/element/element.dart';
import 'package:build/build.dart';
import 'package:fuzz/fuzz.dart';
import 'package:json_serializable/src/json_serializable_generator.dart';
import 'package:source_gen/source_gen.dart';

class _FakeBuildStep implements BuildStep {
  @override
  Object? noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

FutureOr<String> _generate(LibraryElement library, String _) =>
    JsonSerializableGenerator().generate(
      LibraryReader(library),
      _FakeBuildStep(),
    );

Future<void> main() async {
  final axes = cartesianProduct<String, String>({
    'fieldType': ['int', 'int?', 'List<int?>', 'Map<String, int?>'],
    'includeIfNull': ['null', 'true', 'false'],
    'defaultValue': ['none', 'defaultVal'],
  });

  final cases = <CodegenCase>[];
  for (var i = 0; i < axes.length; i++) {
    final combo = axes[i];
    final className = 'FuzzCase$i';
    final type = combo['fieldType']!;
    final inc = combo['includeIfNull']!;
    final hasDefault = combo['defaultValue'] == 'defaultVal';
    // Construct valid declaration + round-trip runtimeCheck for each combo.
    cases.add(
      CodegenCase(
        id: 'case_${i}_${combo.values.join("_")}',
        declarations: '''
@JsonSerializable(includeIfNull: $inc)
class $className {
  final $type value;
  $className(${hasDefault ? '{this.value = const []}' : 'this.value'});
  factory $className.fromJson(Map<String, dynamic> json) =>
      _\$${className}FromJson(json);
  Map<String, dynamic> toJson() => _\$${className}ToJson(this);
}
''',
        runtimeCheck: '''
final instance = $className(...);
final encoded = instance.toJson();
final decoded = $className.fromJson(encoded);
''',
      ),
    );
  }

  final report = await verifyCodegenBatch(
    packageRoot: '.',
    imports: const [
      "import 'package:json_annotation/json_annotation.dart';",
      "import 'aux_types.dart';",
    ],
    preamble: '''
enum SharedStatus { active, paused }
int sharedFromJson(Object? v) => (v as num).toInt();
Object? sharedToJson(int v) => v;
''',
    auxiliaryFiles: const {
      'aux_types.dart': 'typedef CrossLibInt = int;\n',
    },
    generatePart: _generate,
    cases: cases,
    failOnIssues: false,
  );
  print('Passed ${report.passedCases}/${report.totalCases} cases.');
  if (report.issues.isNotEmpty) {
    print(formatCodegenBatchReport(report));
  }
}
```

> [!IMPORTANT]
>
> - **Place shared top-level helpers in `preamble:` (never inside
>   `cases[0].declarations`)**: When Oracle 1 binary-searches a batch to isolate
>   a generator crash (`sublist(0, mid)` and `sublist(mid)`) or Oracle 2 strips
>   a statically non-compilable case, `preamble` stays at the top of every
>   sub-batch while individual `CodegenCase` entries are added or removed
>   independently.
> - **Expose library-private `_$` helpers via public members when asserting in
>   `runtimeCheck`**: `CodegenCase.runtimeCheck` executes in a separate
>   entrypoint library (`fuzz_batch_main.dart`) that imports `fuzz_batch.dart`.
>   To inspect library-private symbols emitted into `fuzz_batch.g.dart` (such as
>   `_$ClsJsonSchema`, `_$ClsFieldMap`, `_$ClsJsonKeys`, or
>   `_$ClsPerFieldToJson`), expose a public static getter on the test class
>   inside `declarations` (for example,
>   `static Map<String, Object?> get schema => _$ClsJsonSchema;`).

### Phase 3: Understand the Three Built-In Oracles

`verifyCodegenBatch` automatically runs all three verification stages and
isolates failures without aborting the rest of the batch:

1. **Oracle 1 -- Diagnostic Contract & Automatic Crash Bisection
   (`generatorException` / `unexpectedSuccess`)**:
   - Positive cases (`expectedError == null`) run together in one batch. If any
     case causes `generatePart` to throw (such as an unhandled `RangeError`,
     `TypeError`, or unexpected `InvalidGenerationSourceError`),
     `verifyCodegenBatch` automatically **binary-searches** the batch inside the
     same warm `AnalysisContext`, records the exact crashing `CodegenCase`(s),
     and continues verifying all surviving cases.
   - Negative cases (`expectedError: 'must be of type...'`) assert that the
     generator rejects invalid declarations with a matching error message rather
     than crashing with an internal stack trace or silently emitting broken
     code.
2. **Oracle 2 -- Static Soundness (`staticError` via `session.getErrors`)**:
   - Writes `fuzz_batch.dart` and `fuzz_batch.g.dart` (with
     `// ignore_for_file: type=lint` so formatting/style lints never cause
     noise) and checks `AnalysisSession.getErrors` for both `Severity.error` and
     `Severity.warning` (catching `invalid_null_aware_operator`,
     `unnecessary_cast`, `dead_null_aware_expression`, invalid type bounds, and
     leaked private typedefs).
   - Statically non-compilable cases are attributed and automatically stripped
     before launching the runtime isolate so one broken `.g.dart` class never
     blocks runtime checks for the rest of the batch.
3. **Oracle 3 -- Batched Runtime Round-Trip (`runtimeFailure` via
   `Isolate.spawnUri`)**:
   - Wraps every surviving `CodegenCase.runtimeCheck` in an isolated
     `try / catch` inside a single `Isolate.spawnUri` script and verifies
     `fromJson(toJson())` round-trip equivalence at runtime.

> [!NOTE]
>
> Always clean up any temporary scripts created during exploration so the target
> repository's `git status` stays completely clean unless staging a verified bug
> fix and regression test.
