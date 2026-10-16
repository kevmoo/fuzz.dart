@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';

import 'package:analyzer/dart/element/element.dart';
import 'package:build/build.dart';
import 'package:checks/checks.dart';
import 'package:cli_util/cli_util.dart';
import 'package:fuzz/fuzz.dart';
import 'package:source_gen/source_gen.dart';
import 'package:test/scaffolding.dart';

class _TestModel {
  const _TestModel();
}

/// A real `source_gen` [GeneratorForAnnotation] with intentional bug triggers
/// so [verifyCodegenBatch] can test all three verification oracles.
class _DemoModelGenerator extends GeneratorForAnnotation<_TestModel> {
  @override
  String generateForAnnotatedElement(
    Element element,
    ConstantReader annotation,
    BuildStep buildStep,
  ) {
    if (element is! ClassElement) {
      throw InvalidGenerationSourceError(
        '@_TestModel can only be applied to classes.',
        element: element,
      );
    }
    final name = element.name!;
    if (name.contains('CrashGen')) {
      throw RangeError.index(-1, const <int>[], 'simulatedGeneratorBug');
    }
    if (name.contains('BrokenSyntax')) {
      return 'Map<String, Object?> _\$${name}ToMap($name v) => '
          '<String, int>{"x": "notAnInt"};';
    }
    if (name.contains('WarnNullAware')) {
      return '''
Map<String, Object?> _\$${name}ToMap($name v) {
  const nonNull = 42;
  return {'x': ?nonNull};
}
''';
    }
    if (name.contains('CorruptRuntime')) {
      return '''
Map<String, Object?> _\$${name}ToMap($name v) => {'x': -999};
$name _\$${name}FromMap(Map<String, Object?> m) => $name(m['x'] as int);
''';
    }
    return '''
Map<String, Object?> _\$${name}ToMap($name v) => {'x': v.x};
$name _\$${name}FromMap(Map<String, Object?> m) => $name(m['x'] as int);
''';
  }
}

FutureOr<String> _runDemoGenerator(LibraryElement library, String _) =>
    _DemoModelGenerator().generate(LibraryReader(library), _NullBuildStep());

class _NullBuildStep implements BuildStep {
  @override
  Object? noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

const String _testPreamble = '''
class _TestModel {
  const _TestModel();
}
''';

void main() {
  group('cartesianProduct', () {
    test('expands multiple axes deterministically', () {
      final product = cartesianProduct<String, String>({
        'nullability': ['T', 'T?'],
        'container': ['scalar', 'list', 'map'],
      });
      check(product).length.equals(6);
      check(product.first)
          .deepEquals({'nullability': 'T', 'container': 'scalar'});
      check(product.last).deepEquals({'nullability': 'T?', 'container': 'map'});
    });

    test(
      'returns empty list for empty axes map and rejects empty axis values',
      () {
        check(cartesianProduct<String, int>(const {})).isEmpty();
        check(
          () => cartesianProduct<String, int>({
            'a': [1],
            'b': const [],
          }),
        ).throws<ArgumentError>();
      },
    );
  });

  group('verifyCodegenBatch', () {
    test('passes when static analysis, negative diagnostics, and Isolate '
        'round-trips succeed', () async {
      final report = await verifyCodegenBatch(
        preamble: _testPreamble,
        imports: const ["import 'aux_helper.dart';"],
        auxiliaryFiles: const {'aux_helper.dart': 'const int kAuxSeed = 7;\n'},
        generatePart: _runDemoGenerator,
        cases: const [
          CodegenCase(
            id: 'valid_alpha',
            declarations: r'''
@_TestModel()
class ValidAlpha {
  final int x;
  ValidAlpha(this.x);
  Map<String, Object?> toMap() => _$ValidAlphaToMap(this);
  factory ValidAlpha.fromMap(Map<String, Object?> m) => _$ValidAlphaFromMap(m);
}
''',
            runtimeCheck: r'''
final orig = ValidAlpha(kAuxSeed);
final decoded = ValidAlpha.fromMap(orig.toMap());
if (decoded.x != kAuxSeed) throw StateError('Mismatch: ${decoded.x}');
''',
          ),
          CodegenCase(
            id: 'invalid_enum_target',
            declarations: '''
@_TestModel()
enum NotAClass { a, b }
''',
            expectedError: '@_TestModel can only be applied to classes.',
          ),
        ],
      );

      check(report.totalCases).equals(2);
      check(report.passedCases).equals(2);
      check(report.issues).isEmpty();
    });

    test('bisects generator crashes, attributes static errors/warnings, and '
        'isolates runtime failures in one batch', () async {
      final report = await verifyCodegenBatch(
        preamble: _testPreamble,
        generatePart: _runDemoGenerator,
        failOnIssues: false,
        cases: const [
          CodegenCase(
            id: 'good_case',
            declarations: r'''
@_TestModel()
class GoodCase {
  final int x;
  GoodCase(this.x);
  Map<String, Object?> toMap() => _$GoodCaseToMap(this);
  factory GoodCase.fromMap(Map<String, Object?> m) => _$GoodCaseFromMap(m);
}
''',
            runtimeCheck: '''
final v = GoodCase.fromMap(GoodCase(123).toMap());
if (v.x != 123) throw StateError('Bad round-trip');
''',
          ),
          CodegenCase(
            id: 'crash_gen_case',
            declarations: '''
@_TestModel()
class CrashGenCase {
  final int x;
  CrashGenCase(this.x);
}
''',
          ),
          CodegenCase(
            id: 'static_error_case_1',
            declarations: '''
@_TestModel()
class BrokenSyntaxCase1 {
  final int x;
  BrokenSyntaxCase1(this.x);
}
''',
          ),
          CodegenCase(
            id: 'good_case_10',
            declarations: r'''
@_TestModel()
class BrokenSyntaxCase10 {
  final int x;
  BrokenSyntaxCase10(this.x);
}
''',
          ),
          CodegenCase(
            id: 'runtime_compile_error_case',
            declarations: r'''
@_TestModel()
class ValidModelForBadCheck {
  final int x;
  ValidModelForBadCheck(this.x);
  Map<String, Object?> toMap() => _$ValidModelForBadCheckToMap(this);
}
''',
            runtimeCheck: r'''
final _ = _$NonExistentPrivateSymbol;
''',
          ),
          CodegenCase(
            id: 'static_warning_case',
            declarations: '''
@_TestModel()
class WarnNullAwareCase {
  final int x;
  WarnNullAwareCase(this.x);
}
''',
          ),
          CodegenCase(
            id: 'runtime_fail_case',
            declarations: r'''
@_TestModel()
class CorruptRuntimeCase {
  final int x;
  CorruptRuntimeCase(this.x);
  Map<String, Object?> toMap() => _$CorruptRuntimeCaseToMap(this);
  factory CorruptRuntimeCase.fromMap(Map<String, Object?> m) =>
      _$CorruptRuntimeCaseFromMap(m);
}
''',
            runtimeCheck: r'''
final v = CorruptRuntimeCase.fromMap(CorruptRuntimeCase(10).toMap());
if (v.x != 10) throw StateError('Expected 10, got ${v.x}');
''',
          ),
          CodegenCase(
            id: 'unexpected_success_case',
            declarations: '''
@_TestModel()
class ShouldHaveFailedCase {
  final int x;
  ShouldHaveFailedCase(this.x);
}
''',
            expectedError: 'Expected failure that never happens',
          ),
        ],
      );

      check(report.totalCases).equals(8);
      check(report.passedCases).equals(1);

      final byId = {for (final i in report.issues) i.caseId: i};
      check(byId.containsKey('good_case')).isFalse();
      check(byId['crash_gen_case']?.kind)
          .equals(CodegenIssueKind.generatorException);
      check(byId['static_error_case_1']?.kind)
          .equals(CodegenIssueKind.staticError);
      check(byId['static_error_case_1']!.generatedCode)
          .isNotNull()
          .not((it) => it.contains('BrokenSyntaxCase10'));
      check(byId['runtime_compile_error_case']?.kind)
          .equals(CodegenIssueKind.staticError);
      check(byId['runtime_compile_error_case']!.message)
          .contains('fuzz_batch_main.dart:');
      check(byId['static_warning_case']?.kind)
          .equals(CodegenIssueKind.staticError);
      check(byId['static_warning_case']!.message)
          .contains('invalid_null_aware_operator');
      check(byId['runtime_fail_case']?.kind)
          .equals(CodegenIssueKind.runtimeFailure);
      check(byId['runtime_fail_case']!.message)
          .contains('Expected 10, got -999');
      check(byId['unexpected_success_case']?.kind)
          .equals(CodegenIssueKind.unexpectedSuccess);
    });

    test(
      'fuzz codegen CLI executes a script with injected package_config',
      () async {
        final tmpDir = Directory.systemTemp.createTempSync('fuzz_codegen_cli_');
        try {
          final scriptFile = File('${tmpDir.path}/smoke_codegen.dart')
            ..writeAsStringSync('''
import 'package:fuzz/fuzz.dart';

void main() {
  final combos = cartesianProduct({'a': [1, 2], 'b': [3, 4]});
  if (combos.length != 4) throw StateError('Expected 4 combos');
  print('CODEGEN_CLI_OK');
}
''');
          final dartBin = dartExecutable!;
          final res = await Process.run(dartBin, [
            'bin/fuzz.dart',
            'codegen',
            scriptFile.path,
          ]);
          check(res.exitCode).equals(0);
          check(res.stdout as String).contains('CODEGEN_CLI_OK');
        } finally {
          if (tmpDir.existsSync()) tmpDir.deleteSync(recursive: true);
        }
      },
    );
  });
}
