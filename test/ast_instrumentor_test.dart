@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:fuzz/src/coverage_report.dart';
import 'package:fuzz/src/fuzz_runtime.dart';
import 'package:fuzz/src/instrument_ast.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'package:test_descriptor/test_descriptor.dart' as d;

void main() {
  group('AstInstrumentor', () {
    test(
      'instruments edges, comparisons, and switches while preserving consts',
      () {
        const sample = '''
library sample;

const int kMagic = 1 + 2;

class Demo {
  const Demo([int x = 3 == 3 ? 1 : 0]);
}

int check(int a, String s) {
  if (a == 42) return 1;
  switch (s) {
    case 'foo':
      return 2;
    default:
      return a ^ 7;
  }
}
''';
        final instrumentor = AstInstrumentor();
        final out = instrumentor.instrumentSource(sample);

        expect(out, contains("import 'package:fuzz/src/fuzz_runtime.dart';"));
        expect(out, contains(r'$fuzzEdge('));
        expect(out, contains(r'$fuzzEq(a, 42,'));
        expect(out, contains(r'$fuzzSwitch(s,'));
        expect(out, contains(r'$fuzzXor(a, 7,'));
        expect(out, contains('const int kMagic = 1 + 2;'));
        expect(out, contains('const Demo([int x = 3 == 3 ? 1 : 0]);'));

        final parsed = parseString(content: out);
        expect(parsed.errors, isEmpty);
        expect(instrumentor.edgesInserted, greaterThan(0));
        expect(instrumentor.comparesInserted, equals(2));
        expect(instrumentor.switchesInserted, equals(1));
      },
    );

    test(
      'omits import directive in `part of` files to preserve valid syntax',
      () {
        const partSample = '''
part of 'sample.dart';

bool isHeaderByte(int b) {
  if (b == 0xFE) return true;
  return b < 0x20;
}
''';
        final instrumentor = AstInstrumentor();
        final out = instrumentor.instrumentSource(partSample);

        expect(out, isNot(contains('import ')));
        expect(out, contains('// ignore_for_file: type=lint'));
        expect(out, contains(r'$fuzzEq(b, 0xFE,'));
        expect(out, contains(r'$fuzzLt(b, 0x20,'));

        final parsed = parseString(content: out);
        expect(parsed.errors, isEmpty);
      },
    );

    test('returns 0-edit barrel/const and part-of files unmodified while '
        'preserving import on files with `part` directives', () {
      const barrelSample = '''
export 'src/a.dart';
export 'src/b.dart';

const int kVersion = 1;
''';
      final barrelInstrumentor = AstInstrumentor();
      final barrelOut = barrelInstrumentor.instrumentSource(barrelSample);
      expect(barrelOut, equals(barrelSample));
      expect(barrelOut, isNot(contains('fuzz_runtime.dart')));

      const zeroEditPartOfSample = '''
part of 'parent.dart';

const int kPartConst = 42;
''';
      final zeroEditPartOfOut = AstInstrumentor().instrumentSource(
        zeroEditPartOfSample,
      );
      expect(zeroEditPartOfOut, equals(zeroEditPartOfSample));
      expect(zeroEditPartOfOut, isNot(contains('ignore_for_file')));

      const parentWithPartSample = '''
library parent;

part 'src/child.dart';
''';
      final parentInstrumentor = AstInstrumentor();
      final parentOut = parentInstrumentor.instrumentSource(
        parentWithPartSample,
      );
      expect(
        parentOut,
        contains(
          "import 'package:fuzz/src/fuzz_runtime.dart'; "
          '// ignore_for_file: type=lint, unused_import, duplicate_ignore',
        ),
      );
    });

    test(
      'preserves == null and != null for Dart flow-analysis type promotion',
      () {
        const nullPromotionSample = '''
int promotedLength(String? value, bool flag) {
  if (value != null && flag == true) {
    return value.length;
  }
  return 0;
}
''';
        final instrumentor = AstInstrumentor();
        final out = instrumentor.instrumentSource(nullPromotionSample);

        expect(out, contains('value != null'));
        expect(out, contains('flag == true'));
        expect(out, isNot(contains(r'$fuzzNe(value, null')));
        expect(out, isNot(contains(r'$fuzzEq(flag, true')));
        expect(instrumentor.comparesInserted, equals(0));
        expect(instrumentor.edgesInserted, greaterThan(0));
      },
    );

    test(
      'preserves ConstantPattern in if-case and instruments switch when guards',
      () {
        const patternSample = '''
int evalPattern(int x) {
  if (x case const (1 ^ 2)) {
    return 1;
  }
  switch (x) {
    case var v when v > 10 && v == 42:
      return 2;
    default:
      return 0;
  }
}
''';
        final instrumentor = AstInstrumentor();
        final out = instrumentor.instrumentSource(patternSample);

        // ConstantPattern inside if-case must stay a valid constant expression.
        expect(out, contains('if (x case const (1 ^ 2))'));
        expect(out, isNot(contains(r'const ($fuzzXor')));

        // Runtime guard expression in `when` clause must be instrumented.
        expect(out, contains(r'$fuzzGt(v, 10,'));
        expect(out, contains(r'$fuzzEq(v, 42,'));

        final parsed = parseString(content: out);
        expect(parsed.errors, isEmpty);
      },
    );

    test(
      r'skips instrumenting AssertStatement and records both bits in $fuzzXor',
      () {
        const sample = '''
int check(int a, int b) {
  assert(a == b && a > 0);
  return a ^ b;
}
''';
        final instrumentor = AstInstrumentor();
        final out = instrumentor.instrumentSource(sample);

        expect(out, contains('assert(a == b && a > 0);'));
        expect(out, isNot(contains(r'$fuzzEq')));
        expect(out, isNot(contains(r'$fuzzGt')));
        expect(out, contains(r'$fuzzXor(a, b,'));
        expect(instrumentor.comparesInserted, equals(1));

        final xorSiteId = instrumentor.sites
            .singleWhere((s) => s.kind == 'cmp')
            .id;
        $fuzzSiteHits[xorSiteId] = 0;
        expect($fuzzXor(5, 5, xorSiteId), equals(0));
        expect($fuzzSiteHits[xorSiteId], equals(1));
        expect($fuzzXor(5, 3, xorSiteId), equals(6));
        expect($fuzzSiteHits[xorSiteId], equals(3));
      },
    );

    test(
      r'instruments SwitchExpression cases with $fuzzExpr and unwraps throw',
      () {
        const sample = '''
String describeCode(int code) => switch (code) {
  200 => 'ok',
  404 || 410 => 'missing',
  var c when c >= 500 => 'server_error',
  _ => throw ArgumentError.value(code, 'code'),
};
''';
        final instrumentor = AstInstrumentor();
        final out = instrumentor.instrumentSource(sample);

        // The outer arrow body and the 3 non-throw case arms are wrapped with
        // $fuzzExpr; the throw arm is unwrapped as `throw $fuzzExpr(id, ...)`.
        expect(out, contains(r'=> $fuzzExpr('));
        expect(out, contains(r"=> $fuzzExpr(15470, 'ok')"));
        expect(out, contains(r"=> $fuzzExpr(55973, 'missing')"));
        expect(
          out,
          contains(
            r'var c when $fuzzGe(c, 500, 46410) => '
            r"$fuzzExpr(30940, 'server_error')",
          ),
        );
        expect(
          out,
          contains(
            r"_ => throw $fuzzExpr(5907, ArgumentError.value(code, 'code'))",
          ),
        );

        final parsed = parseString(content: out);
        expect(parsed.errors, isEmpty);
        expect(instrumentor.edgesInserted, equals(5));
        expect(instrumentor.comparesInserted, equals(1));
      },
    );

    test('instruments ConditionalExpression and ExpressionFunctionBody with '
        r'$fuzzExpr including nested shared-offset expressions', () {
      const sample = '''
int clampSign(int x, bool neg, bool zero) =>
    zero ? 0 : neg ? -x : x;
''';
      final instrumentor = AstInstrumentor();
      final out = instrumentor.instrumentSource(sample);

      expect(out, contains(r'$fuzzBool(zero,'));
      expect(out, contains(r'$fuzzBool(neg,'));
      expect(out, contains(r'$fuzzExpr('));

      final parsed = parseString(content: out);
      expect(parsed.errors, isEmpty);
      // 1 arrow body + 2 outer ternary arms + 2 inner ternary arms = 5 edges.
      expect(instrumentor.edgesInserted, equals(5));
      // 2 non-binary conditions (`zero` and `neg`) = 2 cmp sites.
      expect(instrumentor.comparesInserted, equals(2));
    });

    test(r'wraps non-binary conditions in $fuzzBool while preserving type '
        'promotions and boolean literals', () {
      const sample = '''
int scanItems(List<int> items, Object? maybeText) {
  if (items.isEmpty) return 0;
  if (maybeText is String) {
    return maybeText.length;
  }
  if (!(maybeText != null)) {
    return -1;
  }
  while (true) {
    if (items.first.isEven) break;
    return 1;
  }
  return 2;
}
''';
      final instrumentor = AstInstrumentor();
      final out = instrumentor.instrumentSource(sample);

      expect(out, contains(r'if ($fuzzBool(items.isEmpty,'));
      expect(out, contains(r'if ($fuzzBool(items.first.isEven,'));
      // Type-promotion conditions (`is`, `!= null`) and `while (true)` must
      // not be wrapped in $fuzzBool.
      expect(out, contains('if (maybeText is String)'));
      expect(out, contains('if (!(maybeText != null))'));
      expect(out, contains('while (true)'));
      expect(out, isNot(contains(r'$fuzzBool(true')));

      final parsed = parseString(content: out);
      expect(parsed.errors, isEmpty);
      expect(instrumentor.comparesInserted, equals(2));
    });

    test(
      r'wraps braceless for, while, and do loop bodies with $fuzzEdge blocks',
      () {
        const sample = '''
int sumUp(List<int> xs) {
  var total = 0;
  for (var i = 0; i < xs.length; i++) total += xs[i];
  while (total > 100) total -= 10;
  do total++; while (total < 10);
  return total;
}
''';
        final instrumentor = AstInstrumentor();
        final out = instrumentor.instrumentSource(sample);

        expect(out, contains(r'{ $fuzzEdge(15470); total += xs[i]; }'));
        expect(out, contains(r'{ $fuzzEdge(30940); total -= 10; }'));
        expect(out, contains(r'{ $fuzzEdge(46410); total++; }'));

        final parsed = parseString(content: out);
        expect(parsed.errors, isEmpty);
        // 1 function body + 3 braceless loop bodies = 4 edges.
        expect(instrumentor.edgesInserted, equals(4));
        // 3 binary loop conditions = 3 cmp sites.
        expect(instrumentor.comparesInserted, equals(3));
      },
    );

    test('preserves flow promotions in ConditionalExpression branches, unwraps '
        'parenthesized throws, skips all-throwing outer wrappers and async=>, '
        r'and supports bool $fuzzXor and PatternAssignment conditions', () {
      const sample = r'''
Future<void> asyncVoidArrow(String msg) async => print(msg);

int condPromotion(int? x, bool flag) {
  if (flag ? x != null : false) {
    return x;
  }
  if ((flag ? x is int : false) && x.isEven) {
    return x;
  }
  return 0;
}

Never alwaysThrowsSwitch(int code) => switch (code) {
  0 => throw StateError('0'),
  _ => (throw ArgumentError('other')),
};

bool checkBoolXor(bool a, bool b, List<(int?, bool)> items) {
  int? x;
  var ok = false;
  while (((x, ok) = items.first).$2) {
    if (a ^ b) return x != null;
  }
  return false;
}

int nullAwareAssignPromotion(int? position, RegExpMatch? match) {
  position ??= match == null ? 0 : match.start;
  return position + 1;
}

class _SubEq {
  @override
  bool operator ==(Object other) => super == other;
}
''';
      final instrumentor = AstInstrumentor();
      final out = instrumentor.instrumentSource(sample);

      // async => is not wrapped in $fuzzExpr to preserve void expressions.
      expect(
        out,
        contains(
          'Future<void> asyncVoidArrow(String msg) async => print(msg);',
        ),
      );
      // ConditionalExpression branches with `!= null`, `is`, or `false` stay
      // unwrapped so Dart flow-analysis type promotion is preserved.
      expect(out, contains(r'if ($fuzzBool(flag, 15470) ? x != null : false)'));
      expect(
        out,
        contains(
          r'if (($fuzzBool(flag, 30940) ? x is int : false) && x.isEven)',
        ),
      );
      // All-throwing SwitchExpression omits an unreachable outer $fuzzExpr
      // while unwrapping parenthesized `(throw ...)` inside its arm.
      expect(
        out,
        contains(r'Never alwaysThrowsSwitch(int code) => switch (code) {'),
      );
      expect(
        out,
        contains(r"_ => (throw $fuzzExpr(21377, ArgumentError('other')))"),
      );
      // PatternAssignment loop condition is not wrapped in $fuzzBool, and
      // `a ^ b` uses generic `$fuzzXor`.
      expect(out, contains(r'while (((x, ok) = items.first).$2)'));
      expect(out, contains(r'if ($fuzzXor(a, b, 52317))'));
      // AssignmentExpression RHS ConditionalExpression arms stay unwrapped so
      // downward context `int?` does not widen `$fuzzExpr<T>` and block LHS
      // promotion to `int`.
      expect(out, contains('position ??= match == null ? 0 : match.start;'));
      // `super == other` is not rewritten into `$fuzzEq(super, other, id)`.
      expect(out, contains('super == other'));
      expect(out, isNot(contains(r'$fuzzEq(super,')));

      final parsed = parseString(content: out);
      expect(parsed.errors, isEmpty);

      // Verify generic $fuzzXor on bool operands.
      $fuzzSiteHits[52317] = 0;
      expect($fuzzXor(true, false, 52317), isTrue);
      expect($fuzzSiteHits[52317], equals(1));
      expect($fuzzXor(true, true, 52317), isFalse);
      expect($fuzzSiteHits[52317], equals(3));
    });

    test(
      'preserves const RecordLiteral, VariableDeclaration & switch promotions, '
      'dot shorthands, void/FutureOr<void> arrow bodies, and instruments '
      '&& / || boolean clauses',
      () {
        const sample = '''
import 'dart:async';

enum _Color { red, blue }

const (bool, int) kRecord = const (1 == 1, 2 ^ 3);

FutureOr<void> syncFutureOrVoid(String s) => print(s);

void runClosure(String s) {
  Future.sync(() => print(s));
}

int promoteVarDeclAndSwitch(int? a, int? b, Object c, bool flag, _Color col) {
  int? promoted = flag ? 10 : 20;
  var total = promoted + 1;
  switch (a) {
    case null:
      return 0;
    default:
      total += a + 1;
  }
  switch (c) {
    case int():
      total += c + 1;
    default:
      break;
  }
  if (col == .red) {
    return total;
  }
  switch (col) {
    case .blue:
      return total + 1;
    default:
      break;
  }
  if (total.isEven && total.isFinite) {
    return total + (b ?? 0);
  }
  return total;
}
''';
        final instrumentor = AstInstrumentor();
        final out = instrumentor.instrumentSource(sample);

        // 1. const RecordLiteral must not be instrumented.
        expect(out, contains('const (1 == 1, 2 ^ 3)'));
        // 2. FutureOr<void> and closure => print(s) must not be wrapped in
        // $fuzzExpr.
        expect(
          out,
          contains('FutureOr<void> syncFutureOrVoid(String s) => print(s);'),
        );
        expect(out, contains('Future.sync(() => print(s));'));
        // 3. VariableDeclaration initializer ternary arms stay unwrapped so
        // `promoted` promotes from `int?` to `int`.
        expect(
          out,
          contains(r'int? promoted = $fuzzBool(flag, 55973) ? 10 : 20;'),
        );
        // 4. `switch (a)` with `case null:` and `switch (c)` with `case int():`
        // stay unwrapped so `a` and `c` promote in case bodies.
        expect(out, contains('switch (a)'));
        expect(out, isNot(contains(r'$fuzzSwitch(a,')));
        expect(out, contains('switch (c)'));
        expect(out, isNot(contains(r'$fuzzSwitch(c,')));
        // 5. Dot shorthands (`col == .red` and `case .blue:`) stay unwrapped so
        // their context type is preserved.
        expect(out, contains('col == .red'));
        expect(out, isNot(contains(r'$fuzzEq(col, .red')));
        expect(out, isNot(contains(r'$fuzzSwitch(col,')));
        // 6. `&&` boolean sub-clauses are individually wrapped with $fuzzBool.
        expect(out, contains(r'$fuzzBool(total.isEven,'));
        expect(out, contains(r'$fuzzBool(total.isFinite,'));

        final parsed = parseString(content: out);
        expect(parsed.errors, isEmpty);
      },
    );
  });

  group('PackageOverlayInstrumentor', () {
    test('creates non-destructive .dart_tool/fuzz/ overlay and runs '
        'target without analyzer dependency', () async {
      await d.dir('sample_pkg', [
        d.file('pubspec.yaml', '''
name: sample_pkg
environment:
  sdk: ^3.7.0
'''),
        d.dir('.dart_tool', [
          d.file(
            'package_config.json',
            jsonEncode({
              'configVersion': 2,
              'packages': [
                {
                  'name': 'sample_pkg',
                  'rootUri': '../',
                  'packageUri': 'lib/',
                  'languageVersion': '3.7',
                },
              ],
            }),
          ),
        ]),
        d.dir('lib', [
          d.file('sample_pkg.dart', '''
library sample_pkg;

part 'src/part_file.dart';

int parseRoot(int x) {
  if (x == 10) {
    return _parsePart(x);
  }
  switch (x) {
    case 1:
      return 1;
    default:
      return 0;
  }
}
'''),
          d.dir('src', [
            d.file('part_file.dart', '''
part of '../sample_pkg.dart';

int _parsePart(int x) => x > 5 ? 1 : 0;
'''),
          ]),
        ]),
        d.dir('test', [
          d.file('smoke_target.dart', '''
import 'package:sample_pkg/sample_pkg.dart';

void main() {
  if (parseRoot(10) != 1) throw StateError('unexpected');
}
'''),
        ]),
      ]).create();

      final pkgRoot = p.join(d.sandbox, 'sample_pkg');
      final originalLib = File(p.join(pkgRoot, 'lib', 'sample_pkg.dart'))
          .readAsStringSync();

      final res = await PackageOverlayInstrumentor.instrumentPackage(
        packageRoot: pkgRoot,
      );

      expect(res.packageName, equals('sample_pkg'));
      expect(res.filesInstrumented, equals(2));
      expect(res.edgesInserted, greaterThan(0));
      expect(res.comparesInserted, equals(2));
      expect(res.switchesInserted, equals(1));

      // Original source in lib/ must remain 100% untouched.
      expect(
        File(p.join(pkgRoot, 'lib', 'sample_pkg.dart')).readAsStringSync(),
        equals(originalLib),
      );

      // Instrumented library root has import; part file does not.
      final instRoot = File(p.join(res.instrumentedLibDir, 'sample_pkg.dart'))
          .readAsStringSync();
      final instPart = File(
        p.join(res.instrumentedLibDir, 'src', 'part_file.dart'),
      ).readAsStringSync();
      expect(
        instRoot,
        contains("import 'package:fuzz/src/fuzz_runtime.dart';"),
      );
      expect(instPart, isNot(contains('import ')));
      expect(instPart, contains(r'$fuzzGt(x, 5,'));

      // Overlay package_config.json preserves sample_pkg rootUri and remaps
      // packageUri to .dart_tool/fuzz/instrumented/lib/.
      final overlayJson = jsonDecode(
        File(res.overlayPackageConfigPath).readAsStringSync(),
      ) as Map<String, Object?>;
      final packages = (overlayJson['packages'] as List<Object?>)
          .cast<Map<String, Object?>>();
      final sampleEntry = packages.singleWhere(
        (e) => e['name'] == 'sample_pkg',
      );
      final fuzzEntry = packages.singleWhere((e) => e['name'] == 'fuzz');
      expect(
        sampleEntry['rootUri'] as String,
        equals(p.toUri(pkgRoot).toString()),
      );
      expect(
        sampleEntry['packageUri'],
        equals('.dart_tool/fuzz/instrumented/lib/'),
      );
      expect(fuzzEntry['packageUri'], equals('lib/'));

      // Verify child Dart VM compiles and executes test/smoke_target.dart
      // using the overlay package_config.json without package:analyzer.
      final vmRes = await Process.run(Platform.resolvedExecutable, [
        '--packages=${res.overlayPackageConfigPath}',
        p.join(pkgRoot, 'test', 'smoke_target.dart'),
      ], workingDirectory: pkgRoot);
      expect(vmRes.exitCode, equals(0), reason: '${vmRes.stderr}');

      // edge_manifest.json records all sites and computes exact per-file stats,
      // including K&R block lines and totalEdges == edgesInserted.
      final manifestJson = File(res.edgeManifestPath).readAsStringSync();
      $fuzzSiteHits.fillRange(0, FuzzRuntime.numCounters, 0);
      final manifestMap = jsonDecode(manifestJson) as Map<String, Object?>;
      final sites = (manifestMap['sites'] as List<Object?>)
          .cast<Map<String, Object?>>();
      expect(
        sites.length,
        equals(res.edgesInserted + res.comparesInserted + res.switchesInserted),
      );

      final firstId = sites.first['id'] as int;
      $fuzzEdge(firstId);
      final report = computeCoverageReport(
        edgeManifestJson: manifestJson,
        siteHits: $fuzzSiteHits,
      );
      expect(report.packageName, equals('sample_pkg'));
      expect(report.hitSites, equals(1));
      expect(report.totalSites, equals(sites.length));
      expect(report.totalEdges, equals(res.edgesInserted));
      expect(report.totalCompares, equals(res.comparesInserted));
      expect(report.files.first.uncoveredLines, contains(7));
      expect(report.files.map((f) => f.file), [
        'lib/sample_pkg.dart',
        'lib/src/part_file.dart',
      ]);
      expect(formatCoverageTable(report), contains('lib/sample_pkg.dart'));
    });

    test('instruments additionalPackages from package_config.json and isolates '
        'custom workDir without collision', () async {
      await d.dir('workspace', [
        d.dir('dep_pkg', [
          d.file('pubspec.yaml', '''
name: dep_pkg
environment:
  sdk: ^3.7.0
'''),
          d.dir('lib', [
            d.file('dep_pkg.dart', '''
int parseDelegated(String input) {
  if (input == 'YAML') return 42;
  return 0;
}
'''),
          ]),
        ]),
        d.dir('host_pkg', [
          d.file('pubspec.yaml', '''
name: host_pkg
environment:
  sdk: ^3.7.0
'''),
          d.dir('.dart_tool', [
            d.file(
              'package_config.json',
              jsonEncode({
                'configVersion': 2,
                'packages': [
                  {
                    'name': 'host_pkg',
                    'rootUri': '../',
                    'packageUri': 'lib/',
                    'languageVersion': '3.7',
                  },
                  {
                    'name': 'dep_pkg',
                    'rootUri': '../../dep_pkg',
                    'packageUri': 'lib/',
                    'languageVersion': '3.7',
                  },
                ],
              }),
            ),
          ]),
          d.dir('lib', [
            d.file('host_pkg.dart', '''
import 'package:dep_pkg/dep_pkg.dart';

int parseHost(String s) {
  if (s.isEmpty) return -1;
  return parseDelegated(s);
}
'''),
          ]),
          d.dir('test', [
            d.file('delegate_target.dart', '''
import 'package:host_pkg/host_pkg.dart';

void main() {
  if (parseHost('YAML') != 42) throw StateError('unexpected');
}
'''),
          ]),
        ]),
      ]).create();

      final hostRoot = p.join(d.sandbox, 'workspace', 'host_pkg');
      final customWorkDir = p.join(d.sandbox, 'custom_work_dir');

      final res = await PackageOverlayInstrumentor.instrumentPackage(
        packageRoot: hostRoot,
        workDir: customWorkDir,
        additionalPackages: const ['dep_pkg'],
      );

      // Both host_pkg (1 file) and dep_pkg (1 file) must be instrumented.
      expect(res.filesInstrumented, equals(2));
      expect(
        res.overlayPackageConfigPath,
        equals(p.join(customWorkDir, 'package_config.json')),
      );

      // Default .dart_tool/fuzz directory inside host_pkg must not be created
      // when custom workDir is used.
      expect(
        Directory(p.join(hostRoot, '.dart_tool', 'fuzz')).existsSync(),
        isFalse,
      );

      // Verify the child Dart VM resolves both instrumented packages and runs.
      final vmRes = await Process.run(Platform.resolvedExecutable, [
        '--packages=${res.overlayPackageConfigPath}',
        p.join(hostRoot, 'test', 'delegate_target.dart'),
      ], workingDirectory: hostRoot);
      expect(vmRes.exitCode, equals(0), reason: '${vmRes.stderr}');

      // Verify edge_manifest.json includes sites for both host_pkg and dep_pkg.
      final manifestMap = jsonDecode(
        File(res.edgeManifestPath).readAsStringSync(),
      ) as Map<String, Object?>;
      final siteFiles = (manifestMap['sites'] as List<Object?>)
          .cast<Map<String, Object?>>()
          .map((s) => s['file'] as String)
          .toSet();
      expect(siteFiles, contains('lib/host_pkg.dart'));
      expect(siteFiles, contains('package:dep_pkg/lib/dep_pkg.dart'));
      expect(res.dictionaryTokensExtracted, greaterThanOrEqualTo(1));
      expect(File(res.dictionaryPath).existsSync(), isTrue);
      expect(File(res.dictionaryPath).readAsStringSync(), contains('"YAML"'));
    });

    test(
      'harvests AST string literals, RegExp alternations, and ASCII char '
      'constants while excluding directives, >32 lookup tables, and errors',
      () {
        final largeTableEntries = List.generate(
          40,
          (i) => "'emoji_$i': 'VAL_$i'",
        ).join(', ');
        final sample =
            '''
import 'dart:convert';

final _weekdayRe = RegExp(r'Mon|Tue|Wed');
final _digitsRe = RegExp(r'\\d+\\r\\n');
const _hugeTable = <String, String>{$largeTableEntries};

int parseHeader(String line, int byte) {
  if (line == '<<MAGIC>>' || line == 'A\\r\\nB') return 1;
  if (byte == 0x25) return 2;
  wrapFormatException('HTTP date', line);
  throw const FormatException('Do not put this error prose in dict');
}

void wrapFormatException(String label, String input) {}
''';
        final instrumentor = AstInstrumentor()..instrumentSource(sample);
        expect(
          instrumentor.dictionaryTokens,
          containsAll([
            '<<MAGIC>>',
            'A\r\nB',
            '%',
            'Mon',
            'Tue',
            'Wed',
            '0',
            '\r\n',
          ]),
        );
        expect(instrumentor.dictionaryTokens, isNot(contains('dart:convert')));
        expect(instrumentor.dictionaryTokens, isNot(contains('HTTP date')));
        expect(instrumentor.dictionaryTokens, isNot(contains('emoji_0')));
        expect(instrumentor.dictionaryTokens, isNot(contains(r'\d+\r\n')));
        expect(
          instrumentor.dictionaryTokens,
          isNot(contains('Do not put this error prose in dict')),
        );

        final formatted = formatFuzzDictionary(instrumentor.dictionaryTokens);
        expect(formatted, contains('"<<MAGIC>>"'));
        expect(formatted, contains(r'"A\x0d\x0aB"'));
        expect(formatted, contains('"%"'));
      },
    );

    test('fuzz run synthesizes fuzz_entrypoint.dart for zero-dependency '
        'void fuzzTarget(Uint8List) targets', () async {
      await d.dir('zero_dep_pkg', [
        d.file('pubspec.yaml', '''
name: zero_dep_pkg
environment:
  sdk: ^3.7.0
'''),
        d.dir('.dart_tool', [
          d.file(
            'package_config.json',
            jsonEncode({
              'configVersion': 2,
              'packages': [
                {
                  'name': 'zero_dep_pkg',
                  'rootUri': '../',
                  'packageUri': 'lib/',
                  'languageVersion': '3.7',
                },
              ],
            }),
          ),
        ]),
        d.dir('lib', [
          d.file('zero_dep_pkg.dart', '''
import 'dart:typed_data';

void checkBytes(Uint8List bytes) {
  if (bytes.isNotEmpty && bytes[0] == 0x41) {
    return;
  }
}
'''),
        ]),
        d.dir('test', [
          d.dir('fuzz', [
            d.file('zero_dep_fuzz.dart', '''
import 'dart:typed_data';
import 'package:zero_dep_pkg/zero_dep_pkg.dart';

void fuzzTarget(Uint8List bytes) {
  checkBytes(bytes);
}
'''),
          ]),
        ]),
      ]).create();

      final pkgRoot = p.join(d.sandbox, 'zero_dep_pkg');
      final fuzzBin = p.join(Directory.current.path, 'bin', 'fuzz.dart');
      final corpusDir = p.join(pkgRoot, '.dart_tool', 'fuzz', 'custom_corpus');
      final res = await Process.run(Platform.resolvedExecutable, [
        fuzzBin,
        'run',
        '--package-root=$pkgRoot',
        '--mode=pure-dart',
        '--runs=20',
        'test/fuzz/zero_dep_fuzz.dart',
        corpusDir,
      ]);
      expect(
        res.exitCode,
        equals(0),
        reason: 'stdout:\n${res.stdout}\nstderr:\n${res.stderr}',
      );
      expect(
        File(p.join(pkgRoot, '.dart_tool', 'fuzz', 'fuzz_entrypoint.dart'))
            .existsSync(),
        isTrue,
      );
      expect(
        Directory(p.join(pkgRoot, '.dart_tool', 'fuzz', 'crashes'))
            .existsSync(),
        isTrue,
      );
      expect(Directory(corpusDir).existsSync(), isTrue);
    });

    test('fuzz run writes crash artifacts into .dart_tool/fuzz/crashes/ by '
        'default leaving package root clean', () async {
      await d.dir('crash_pkg', [
        d.file('pubspec.yaml', 'name: crash_pkg\n'),
        d.dir('.dart_tool', [
          d.file(
            'package_config.json',
            jsonEncode({
              'configVersion': 2,
              'packages': [
                {
                  'name': 'crash_pkg',
                  'rootUri': '../',
                  'packageUri': 'lib/',
                  'languageVersion': '3.7',
                },
              ],
            }),
          ),
        ]),
        d.dir('lib', [
          d.file('crash_pkg.dart', '''
void triggerCrash() {
  throw StateError('boom');
}
'''),
        ]),
        d.dir('test', [
          d.dir('fuzz', [
            d.file('crash_fuzz.dart', '''
import 'dart:typed_data';
import 'package:crash_pkg/crash_pkg.dart';

void fuzzTarget(Uint8List bytes) {
  triggerCrash();
}
'''),
          ]),
        ]),
      ]).create();

      final pkgRoot = p.join(d.sandbox, 'crash_pkg');
      final fuzzBin = p.join(Directory.current.path, 'bin', 'fuzz.dart');
      final res = await Process.run(Platform.resolvedExecutable, [
        fuzzBin,
        'run',
        '--package-root=$pkgRoot',
        '--mode=pure-dart',
        '--runs=5',
        'test/fuzz/crash_fuzz.dart',
      ]);
      expect(res.exitCode, equals(77), reason: '${res.stderr}');

      // Package root must have zero crash-* files.
      final rootCrashFiles = Directory(pkgRoot)
          .listSync()
          .whereType<File>()
          .where((f) => p.basename(f.path).startsWith('crash-'))
          .toList();
      expect(rootCrashFiles, isEmpty);

      // .dart_tool/fuzz/crashes/ must contain the crash file.
      final crashesDir = Directory(
        p.join(pkgRoot, '.dart_tool', 'fuzz', 'crashes'),
      );
      final crashFiles = crashesDir
          .listSync()
          .whereType<File>()
          .where((f) => p.basename(f.path).startsWith('crash-'))
          .toList();
      expect(crashFiles, hasLength(1));
    });

    test('fuzz run supports -artifact_prefix= override and fails fast on '
        'missing target or reproducer', () async {
      await d.dir('override_pkg', [
        d.file('pubspec.yaml', 'name: override_pkg\n'),
        d.dir('.dart_tool', [
          d.file(
            'package_config.json',
            jsonEncode({
              'configVersion': 2,
              'packages': [
                {
                  'name': 'override_pkg',
                  'rootUri': '../',
                  'packageUri': 'lib/',
                  'languageVersion': '3.7',
                },
              ],
            }),
          ),
        ]),
        d.dir('lib', [
          d.file('override_pkg.dart', '''
void triggerCrash() {
  throw StateError('boom');
}
'''),
        ]),
        d.dir('test', [
          d.dir('fuzz', [
            d.file('crash_fuzz.dart', '''
import 'dart:typed_data';
import 'package:override_pkg/override_pkg.dart';

void fuzzTarget(Uint8List bytes) {
  triggerCrash();
}
'''),
          ]),
        ]),
      ]).create();

      final pkgRoot = p.join(d.sandbox, 'override_pkg');
      final fuzzBin = p.join(Directory.current.path, 'bin', 'fuzz.dart');

      // Explicit -artifact_prefix= overrides the default crashes directory.
      final customArtifactsDir = Directory(p.join(pkgRoot, 'custom_artifacts'))
        ..createSync();
      final customRes = await Process.run(Platform.resolvedExecutable, [
        fuzzBin,
        'run',
        '--package-root=$pkgRoot',
        '--mode=pure-dart',
        '--runs=5',
        'test/fuzz/crash_fuzz.dart',
        '--',
        '-artifact_prefix=${customArtifactsDir.path}/',
      ]);
      expect(customRes.exitCode, equals(77));
      expect(
        customArtifactsDir.listSync().whereType<File>().where(
          (f) => p.basename(f.path).startsWith('crash-'),
        ),
        hasLength(1),
      );

      // Missing <target.dart> positional argument exits with code 64.
      final missingTargetRes = await Process.run(Platform.resolvedExecutable, [
        fuzzBin,
        'run',
        '--package-root=$pkgRoot',
      ]);
      expect(missingTargetRes.exitCode, equals(64));
      expect(
        missingTargetRes.stderr.toString(),
        contains('Missing required positional argument: <target.dart>.'),
      );

      // Missing crash-* reproducer fails fast (exit 64) without creating a
      // directory.
      final missingReproRes = await Process.run(Platform.resolvedExecutable, [
        fuzzBin,
        'run',
        '--package-root=$pkgRoot',
        '--mode=pure-dart',
        'test/fuzz/crash_fuzz.dart',
        'crash-doesnotexist',
      ]);
      expect(missingReproRes.exitCode, equals(64));
      expect(
        missingReproRes.stderr.toString(),
        contains('Reproducer file not found'),
      );
      expect(
        Directory(p.join(pkgRoot, 'crash-doesnotexist')).existsSync(),
        isFalse,
      );
    });
  });
}
