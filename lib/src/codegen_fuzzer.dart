import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:analyzer/dart/analysis/analysis_context.dart';
import 'package:analyzer/dart/analysis/analysis_context_collection.dart';
import 'package:analyzer/dart/analysis/results.dart';
import 'package:analyzer/dart/element/element.dart';
import 'package:analyzer/diagnostic/diagnostic.dart';
import 'package:cli_util/cli_util.dart';
import 'package:path/path.dart' as p;

/// Callback that invokes a code generator on a resolved [library] and returns
/// the generated part file body (for example, the contents of `.g.dart`).
///
/// The returned string does not need to include a `part of` directive;
/// [verifyCodegenBatch] automatically prepends `part of 'fuzz_batch.dart';`
/// when absent.
typedef CodegenPartGenerator = FutureOr<String?> Function(
  LibraryElement library,
  String librarySource,
);

/// Classification of failures caught by [verifyCodegenBatch].
enum CodegenIssueKind {
  /// [CodegenPartGenerator] threw an unexpected exception (or an exception that
  /// did not match [CodegenCase.expectedError]).
  generatorException,

  /// [CodegenCase.expectedError] was specified, but [CodegenPartGenerator]
  /// succeeded without throwing.
  unexpectedSuccess,

  /// `package:analyzer` reported a compile-time error or warning on the
  /// input declarations or generated `.g.dart` part file.
  staticError,

  /// The [CodegenCase.runtimeCheck] snippet threw during `Isolate.spawnUri`
  /// round-trip execution.
  runtimeFailure,
}

/// A single failure caught by [verifyCodegenBatch].
typedef CodegenIssue = ({
  String caseId,
  CodegenIssueKind kind,
  String message,
  String declarations,
  String? generatedCode,
});

/// Aggregate result returned by [verifyCodegenBatch].
typedef CodegenBatchReport = ({
  int totalCases,
  int passedCases,
  List<CodegenIssue> issues,
});

/// A single AST/declaration permutation to validate in [verifyCodegenBatch].
final class CodegenCase {
  /// Unique identifier for this permutation (e.g. `'case_001'`).
  final String id;

  /// Top-level Dart declarations (`@MyAnnotation() class Case001 { ... }`).
  final String declarations;

  /// Optional Dart statements executed inside an `async` block in the batched
  /// `Isolate.spawnUri` runtime oracle.
  final String? runtimeCheck;

  /// When non-null, asserts that [CodegenPartGenerator] throws an exception
  /// whose string representation matches [expectedError].
  final Pattern? expectedError;

  const CodegenCase({
    required this.id,
    required this.declarations,
    this.runtimeCheck,
    this.expectedError,
  });
}

/// Computes the deterministic Cartesian product of named feature [axes].
///
/// Throws an [ArgumentError] if any axis in [axes] has an empty value list.
List<Map<K, V>> cartesianProduct<K, V>(Map<K, List<V>> axes) {
  if (axes.isEmpty) return const [];
  var combinations = <Map<K, V>>[const {}];
  for (final MapEntry(:key, :value) in axes.entries) {
    if (value.isEmpty) {
      throw ArgumentError.value(
        value,
        'axes[$key]',
        'Axis value list must not be empty.',
      );
    }
    combinations = _expandAxis(combinations, key, value);
  }
  return combinations;
}

List<Map<K, V>> _expandAxis<K, V>(
  List<Map<K, V>> current,
  K key,
  List<V> values,
) => [
  for (final prefix in current)
    for (final v in values) {...prefix, key: v},
];

/// Validates a batch of [cases] against a code generator ([generatePart]) using
/// three oracles in a single shared `package:analyzer` context and a single
/// batched `Isolate.spawnUri` execution:
///
/// 1. **Diagnostic Contract Oracle**: Verifies negative cases
///    ([CodegenCase.expectedError]) throw matching generator errors, and
///    automatically bisects any unexpected generator crashes across positive
///    cases.
/// 2. **Static Soundness Oracle**: Feeds the combined declarations and
///    generated `.g.dart` part back into `AnalysisSession.getErrors` to catch
///    compile-time errors and (when [includeWarnings] is `true`) static
///    warnings such as `invalid_null_aware_operator` or `unnecessary_cast`.
/// 3. **Runtime Round-Trip Oracle**: Executes all [CodegenCase.runtimeCheck]
///    blocks in a single `Isolate.spawnUri` invocation, isolating per-case
///    exceptions so one failing case never masks the rest of the batch.
///
/// Throws a [StateError] detailing all discovered issues when [failOnIssues] is
/// `true` and at least one issue is found.
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
}) async {
  if (cases.isEmpty) {
    return (totalCases: 0, passedCases: 0, issues: const <CodegenIssue>[]);
  }
  final absPkgRoot = p.normalize(p.absolute(packageRoot));
  final pkgConfigFile = findPackageConfigFile(absPkgRoot);
  final tempWorkDir = _createCodegenWorkDir(absPkgRoot, workDir);
  try {
    _writeAuxiliaryFiles(tempWorkDir.path, auxiliaryFiles);
    final collection = AnalysisContextCollection(
      includedPaths: [tempWorkDir.path],
      sdkPath: sdkPath,
    );
    final context = collection.contextFor(tempWorkDir.path);
    final issues = <CodegenIssue>[];
    final negativeCases = [
      for (final c in cases)
        if (c.expectedError != null) c,
    ];
    final positiveCases = [
      for (final c in cases)
        if (c.expectedError == null) c,
    ];

    await _verifyNegativeCases(
      context: context,
      workDir: tempWorkDir.path,
      negativeCases: negativeCases,
      generatePart: generatePart,
      imports: imports,
      preamble: preamble,
      issues: issues,
    );

    if (positiveCases.isNotEmpty) {
      await _verifyPositiveCases(
        context: context,
        workDir: tempWorkDir.path,
        packageConfigUri: p.toUri(pkgConfigFile.path),
        positiveCases: positiveCases,
        generatePart: generatePart,
        imports: imports,
        preamble: preamble,
        includeWarnings: includeWarnings,
        isolateTimeout: isolateTimeout,
        issues: issues,
      );
    }

    final failedIds = {for (final issue in issues) issue.caseId};
    final report = (
      totalCases: cases.length,
      passedCases: cases.length - failedIds.length,
      issues: List<CodegenIssue>.unmodifiable(issues),
    );
    if (failOnIssues && issues.isNotEmpty) {
      throw StateError(formatCodegenBatchReport(report));
    }
    return report;
  } finally {
    _cleanupWorkDir(tempWorkDir);
  }
}

int _workDirCounter = 0;

Directory _createCodegenWorkDir(String absPkgRoot, String? explicitWorkDir) {
  _workDirCounter++;
  final stamp = '${DateTime.now().microsecondsSinceEpoch}_$_workDirCounter';
  final baseDir = _resolveBaseWorkDir(absPkgRoot, explicitWorkDir);
  final dir = Directory(p.join(baseDir, 'codegen_$stamp'))
    ..createSync(recursive: true);
  return dir;
}

String _resolveBaseWorkDir(String absPkgRoot, String? explicitWorkDir) {
  if (explicitWorkDir != null && explicitWorkDir.isNotEmpty) {
    return p.normalize(p.absolute(explicitWorkDir));
  }
  final envWorkDir = Platform.environment['FUZZ_WORK_DIR'];
  if (envWorkDir != null && envWorkDir.isNotEmpty) {
    return p.normalize(p.absolute(envWorkDir));
  }
  return p.join(absPkgRoot, '.dart_tool', 'fuzz');
}

void _cleanupWorkDir(Directory workDir) {
  final parent = workDir.parent;
  if (workDir.existsSync()) {
    workDir.deleteSync(recursive: true);
  }
  if (parent.existsSync() &&
      p.basename(parent.path) == 'fuzz' &&
      parent.listSync().isEmpty) {
    parent.deleteSync();
  }
}

void _writeAuxiliaryFiles(String workDir, Map<String, String> auxiliaryFiles) {
  for (final MapEntry(:key, :value) in auxiliaryFiles.entries) {
    final file = File(p.join(workDir, key));
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(value);
  }
}

Future<void> _verifyNegativeCases({
  required AnalysisContext context,
  required String workDir,
  required List<CodegenCase> negativeCases,
  required CodegenPartGenerator generatePart,
  required List<String> imports,
  required String preamble,
  required List<CodegenIssue> issues,
}) async {
  final negPath = p.join(workDir, 'fuzz_negative.dart');
  for (final c in negativeCases) {
    final source = _buildLibrarySource(
      cases: [c],
      imports: imports,
      preamble: preamble,
      includePartDirective: false,
    );
    final library = await _resolveLibraryAtPath(context, negPath, source);
    try {
      final out = await generatePart(library, source);
      issues.add((
        caseId: c.id,
        kind: CodegenIssueKind.unexpectedSuccess,
        message:
            'Expected generator error matching ${c.expectedError}, '
            'but generation succeeded.',
        declarations: c.declarations,
        generatedCode: out,
      ));
    } on Object catch (e) {
      if (!_matchesPattern(e.toString(), c.expectedError!)) {
        issues.add((
          caseId: c.id,
          kind: CodegenIssueKind.generatorException,
          message:
              'Expected error matching ${c.expectedError}, '
              'but caught: $e',
          declarations: c.declarations,
          generatedCode: null,
        ));
      }
    }
  }
}

bool _matchesPattern(String text, Pattern pattern) => switch (pattern) {
  final RegExp re => re.hasMatch(text),
  final String s => text.contains(s),
  _ => pattern.allMatches(text).isNotEmpty,
};

Future<void> _verifyPositiveCases({
  required AnalysisContext context,
  required String workDir,
  required Uri packageConfigUri,
  required List<CodegenCase> positiveCases,
  required CodegenPartGenerator generatePart,
  required List<String> imports,
  required String preamble,
  required bool includeWarnings,
  required Duration isolateTimeout,
  required List<CodegenIssue> issues,
}) async {
  final batchPath = p.join(workDir, 'fuzz_batch.dart');
  final partPath = p.join(workDir, 'fuzz_batch.g.dart');
  final genResult = await _runGeneratorWithBisection(
    context: context,
    batchPath: batchPath,
    cases: positiveCases,
    generatePart: generatePart,
    imports: imports,
    preamble: preamble,
    issues: issues,
  );
  if (genResult.survivors.isEmpty) return;

  final compilable = await _verifyStaticDiagnostics(
    context: context,
    batchPath: batchPath,
    partPath: partPath,
    survivors: genResult.survivors,
    generatedPartBody: genResult.generatedPart,
    generatePart: generatePart,
    imports: imports,
    preamble: preamble,
    includeWarnings: includeWarnings,
    issues: issues,
  );
  if (compilable.survivors.isEmpty) return;

  await _runBatchedIsolateChecks(
    context: context,
    workDir: workDir,
    packageConfigUri: packageConfigUri,
    survivors: compilable.survivors,
    generatedPartBody: compilable.generatedPart,
    imports: imports,
    isolateTimeout: isolateTimeout,
    issues: issues,
  );
}

Future<({List<CodegenCase> survivors, String generatedPart})>
_runGeneratorWithBisection({
  required AnalysisContext context,
  required String batchPath,
  required List<CodegenCase> cases,
  required CodegenPartGenerator generatePart,
  required List<String> imports,
  required String preamble,
  required List<CodegenIssue> issues,
}) async {
  final source = _buildLibrarySource(
    cases: cases,
    imports: imports,
    preamble: preamble,
    includePartDirective: false,
  );
  final library = await _resolveLibraryAtPath(context, batchPath, source);
  try {
    final generated = (await generatePart(library, source)) ?? '';
    return (survivors: cases, generatedPart: generated);
  } on Object catch (e, st) {
    if (cases.length == 1) {
      final single = cases.single;
      issues.add((
        caseId: single.id,
        kind: CodegenIssueKind.generatorException,
        message: '$e\n$st',
        declarations: single.declarations,
        generatedCode: null,
      ));
      return (survivors: const <CodegenCase>[], generatedPart: '');
    }
    final mid = cases.length ~/ 2;
    final left = await _runGeneratorWithBisection(
      context: context,
      batchPath: batchPath,
      cases: cases.sublist(0, mid),
      generatePart: generatePart,
      imports: imports,
      preamble: preamble,
      issues: issues,
    );
    final right = await _runGeneratorWithBisection(
      context: context,
      batchPath: batchPath,
      cases: cases.sublist(mid),
      generatePart: generatePart,
      imports: imports,
      preamble: preamble,
      issues: issues,
    );
    return _recombineSurvivors(
      context: context,
      batchPath: batchPath,
      leftSurvivors: left.survivors,
      rightSurvivors: right.survivors,
      generatePart: generatePart,
      imports: imports,
      preamble: preamble,
      issues: issues,
    );
  }
}

Future<({List<CodegenCase> survivors, String generatedPart})>
_recombineSurvivors({
  required AnalysisContext context,
  required String batchPath,
  required List<CodegenCase> leftSurvivors,
  required List<CodegenCase> rightSurvivors,
  required CodegenPartGenerator generatePart,
  required List<String> imports,
  required String preamble,
  required List<CodegenIssue> issues,
}) async {
  final combined = [...leftSurvivors, ...rightSurvivors];
  if (combined.isEmpty) {
    return (survivors: const <CodegenCase>[], generatedPart: '');
  }
  final retrySource = _buildLibrarySource(
    cases: combined,
    imports: imports,
    preamble: preamble,
    includePartDirective: false,
  );
  final retryLib = await _resolveLibraryAtPath(context, batchPath, retrySource);
  try {
    final retryGen = (await generatePart(retryLib, retrySource)) ?? '';
    return (survivors: combined, generatedPart: retryGen);
  } on Object {
    return _recombineIncrementally(
      context: context,
      batchPath: batchPath,
      baseSurvivors: leftSurvivors,
      candidates: rightSurvivors,
      generatePart: generatePart,
      imports: imports,
      preamble: preamble,
      issues: issues,
    );
  }
}

Future<({List<CodegenCase> survivors, String generatedPart})>
_recombineIncrementally({
  required AnalysisContext context,
  required String batchPath,
  required List<CodegenCase> baseSurvivors,
  required List<CodegenCase> candidates,
  required CodegenPartGenerator generatePart,
  required List<String> imports,
  required String preamble,
  required List<CodegenIssue> issues,
}) async {
  final accepted = [...baseSurvivors];
  var lastGen = '';
  for (final candidate in candidates) {
    final trial = [...accepted, candidate];
    final source = _buildLibrarySource(
      cases: trial,
      imports: imports,
      preamble: preamble,
      includePartDirective: false,
    );
    final lib = await _resolveLibraryAtPath(context, batchPath, source);
    try {
      lastGen = (await generatePart(lib, source)) ?? '';
      accepted.add(candidate);
    } on Object catch (e, st) {
      issues.add((
        caseId: candidate.id,
        kind: CodegenIssueKind.generatorException,
        message: '$e\n$st',
        declarations: candidate.declarations,
        generatedCode: null,
      ));
    }
  }
  return (survivors: accepted, generatedPart: lastGen);
}

typedef _StaticAttributionResult = ({
  List<CodegenIssue> issues,
  Set<String> errorCaseIds,
  bool hasUnattributedHardError,
});

Future<({List<CodegenCase> survivors, String generatedPart})>
_verifyStaticDiagnostics({
  required AnalysisContext context,
  required String batchPath,
  required String partPath,
  required List<CodegenCase> survivors,
  required String generatedPartBody,
  required CodegenPartGenerator generatePart,
  required List<String> imports,
  required String preamble,
  required bool includeWarnings,
  required List<CodegenIssue> issues,
}) async {
  var currentSurvivors = survivors;
  var currentPartBody = generatedPartBody;
  for (var pass = 0; pass < 5 && currentSurvivors.isNotEmpty; pass++) {
    final step = await _runSingleStaticDiagnosticPass(
      context: context,
      batchPath: batchPath,
      partPath: partPath,
      survivors: currentSurvivors,
      generatedPartBody: currentPartBody,
      generatePart: generatePart,
      imports: imports,
      preamble: preamble,
      includeWarnings: includeWarnings,
      issues: issues,
    );
    if (step.done) {
      return (survivors: step.survivors, generatedPart: step.generatedPart);
    }
    currentSurvivors = step.survivors;
    currentPartBody = step.generatedPart;
  }
  return (survivors: currentSurvivors, generatedPart: currentPartBody);
}

Future<({List<CodegenCase> survivors, String generatedPart, bool done})>
_runSingleStaticDiagnosticPass({
  required AnalysisContext context,
  required String batchPath,
  required String partPath,
  required List<CodegenCase> survivors,
  required String generatedPartBody,
  required CodegenPartGenerator generatePart,
  required List<String> imports,
  required String preamble,
  required bool includeWarnings,
  required List<CodegenIssue> issues,
}) async {
  final hasPart = generatedPartBody.trim().isNotEmpty;
  final batchSource = _buildLibrarySource(
    cases: survivors,
    imports: imports,
    preamble: preamble,
    includePartDirective: hasPart,
  );
  final partSource = _formatPartSource(generatedPartBody);
  await _writeAndSyncBatchFiles(
    context: context,
    batchPath: batchPath,
    partPath: partPath,
    batchSource: batchSource,
    partSource: hasPart ? partSource : null,
  );

  final batchDiag = await _collectRelevantDiagnostics(
    context,
    batchPath,
    includeWarnings: includeWarnings,
  );
  final partDiag = hasPart
      ? await _collectRelevantDiagnostics(
          context,
          partPath,
          includeWarnings: includeWarnings,
        )
      : const <Diagnostic>[];

  if (batchDiag.isEmpty && partDiag.isEmpty) {
    return (survivors: survivors, generatedPart: generatedPartBody, done: true);
  }

  final attribution = _attributeDiagnosticsToCases(
    survivors: survivors,
    batchSource: batchSource,
    partSource: partSource,
    batchDiagnostics: batchDiag,
    partDiagnostics: partDiag,
  );
  for (final issue in attribution.issues) {
    _appendUniqueIssue(issues, issue);
  }

  if (attribution.errorCaseIds.isEmpty &&
      !attribution.hasUnattributedHardError) {
    return (survivors: survivors, generatedPart: generatedPartBody, done: true);
  }

  final cleanSurvivors = [
    for (final c in survivors)
      if (!attribution.errorCaseIds.contains(c.id)) c,
  ];
  if (cleanSurvivors.isEmpty || cleanSurvivors.length == survivors.length) {
    return (survivors: const <CodegenCase>[], generatedPart: '', done: true);
  }

  final regen = await _regenerateCleanSurvivors(
    context: context,
    batchPath: batchPath,
    partPath: partPath,
    cleanSurvivors: cleanSurvivors,
    generatePart: generatePart,
    imports: imports,
    preamble: preamble,
  );
  return (
    survivors: regen.survivors,
    generatedPart: regen.generatedPart,
    done: false,
  );
}

Future<void> _writeAndSyncBatchFiles({
  required AnalysisContext context,
  required String batchPath,
  required String partPath,
  required String batchSource,
  required String? partSource,
}) async {
  File(batchPath).writeAsStringSync(batchSource);
  context.changeFile(batchPath);
  if (partSource != null) {
    File(partPath).writeAsStringSync(partSource);
    context.changeFile(partPath);
  } else if (File(partPath).existsSync()) {
    File(partPath).deleteSync();
  }
  await context.applyPendingFileChanges();
}

_StaticAttributionResult _attributeDiagnosticsToCases({
  required List<CodegenCase> survivors,
  required String batchSource,
  required String partSource,
  required List<Diagnostic> batchDiagnostics,
  required List<Diagnostic> partDiagnostics,
}) {
  final caseMap = {for (final c in survivors) c.id: c};
  final symbolMap = _buildSymbolToCaseIdMap(survivors);
  final batchAttr = _attributeDiagnosticList(
    diagnostics: batchDiagnostics,
    fileLabel: 'fuzz_batch.dart',
    partSource: partSource,
    caseMap: caseMap,
    resolveCaseId: (d) =>
        _attributeOffsetInBatch(batchSource, d.offset) ??
        _attributeDiagnosticBySymbol(d.message, symbolMap),
  );
  final partAttr = _attributeDiagnosticList(
    diagnostics: partDiagnostics,
    fileLabel: 'fuzz_batch.g.dart',
    partSource: partSource,
    caseMap: caseMap,
    resolveCaseId: (d) => _attributeDiagnosticInPart(partSource, d, symbolMap),
  );
  final foundIssues = [...batchAttr.issues, ...partAttr.issues];
  final errorCaseIds = {...batchAttr.errorCaseIds, ...partAttr.errorCaseIds};
  final hasUnattributedHardError =
      batchAttr.hasUnattributedHardError || partAttr.hasUnattributedHardError;

  if (hasUnattributedHardError && survivors.length == 1) {
    final only = survivors.single;
    errorCaseIds.add(only.id);
    for (final d in [...batchDiagnostics, ...partDiagnostics]) {
      foundIssues.add(
        _buildStaticIssue(only, d, 'fuzz_batch.g.dart', partSource),
      );
    }
  }

  return (
    issues: foundIssues,
    errorCaseIds: errorCaseIds,
    hasUnattributedHardError: hasUnattributedHardError,
  );
}

_StaticAttributionResult _attributeDiagnosticList({
  required List<Diagnostic> diagnostics,
  required String fileLabel,
  required String partSource,
  required Map<String, CodegenCase> caseMap,
  required String? Function(Diagnostic d) resolveCaseId,
}) {
  final foundIssues = <CodegenIssue>[];
  final errorCaseIds = <String>{};
  var hasUnattributedHardError = false;
  for (final d in diagnostics) {
    final caseId = resolveCaseId(d);
    final matched = caseId != null ? caseMap[caseId] : null;
    if (matched != null) {
      foundIssues.add(_buildStaticIssue(matched, d, fileLabel, partSource));
      if (d.severity == Severity.error) errorCaseIds.add(matched.id);
    } else if (d.severity == Severity.error) {
      hasUnattributedHardError = true;
    }
  }
  return (
    issues: foundIssues,
    errorCaseIds: errorCaseIds,
    hasUnattributedHardError: hasUnattributedHardError,
  );
}

CodegenIssue _buildStaticIssue(
  CodegenCase c,
  Diagnostic d,
  String fileLabel,
  String partSource,
) => (
  caseId: c.id,
  kind: CodegenIssueKind.staticError,
  message: '[$fileLabel:${d.diagnosticCode.lowerCaseName}] ${d.message}',
  declarations: c.declarations,
  generatedCode: _extractCaseGeneratedSnippet(partSource, c),
);

void _appendUniqueIssue(List<CodegenIssue> issues, CodegenIssue candidate) {
  final exists = issues.any(
    (e) =>
        e.caseId == candidate.caseId &&
        e.kind == candidate.kind &&
        e.message == candidate.message,
  );
  if (!exists) issues.add(candidate);
}

Future<({List<CodegenCase> survivors, String generatedPart})>
_regenerateCleanSurvivors({
  required AnalysisContext context,
  required String batchPath,
  required String partPath,
  required List<CodegenCase> cleanSurvivors,
  required CodegenPartGenerator generatePart,
  required List<String> imports,
  required String preamble,
}) async {
  final regenSource = _buildLibrarySource(
    cases: cleanSurvivors,
    imports: imports,
    preamble: preamble,
    includePartDirective: false,
  );
  final regenLib = await _resolveLibraryAtPath(context, batchPath, regenSource);
  final regenPart = (await generatePart(regenLib, regenSource)) ?? '';
  final regenHasPart = regenPart.trim().isNotEmpty;
  File(batchPath).writeAsStringSync(
    _buildLibrarySource(
      cases: cleanSurvivors,
      imports: imports,
      preamble: preamble,
      includePartDirective: regenHasPart,
    ),
  );
  if (regenHasPart) {
    File(partPath).writeAsStringSync(_formatPartSource(regenPart));
  }
  return (survivors: cleanSurvivors, generatedPart: regenPart);
}

Future<List<Diagnostic>> _collectRelevantDiagnostics(
  AnalysisContext context,
  String filePath, {
  required bool includeWarnings,
}) async {
  final res = await context.currentSession.getErrors(filePath);
  if (res is! ErrorsResult) return const [];
  return [
    for (final d in res.diagnostics)
      if (_isRelevantDiagnostic(d, includeWarnings: includeWarnings)) d,
  ];
}

const Set<String> _ignoredWarningCodes = {
  'unused_element',
  'unused_field',
  'unused_local_variable',
};

bool _isRelevantDiagnostic(Diagnostic d, {required bool includeWarnings}) {
  if (d.severity == Severity.error) return true;
  if (!includeWarnings || d.severity != Severity.warning) return false;
  return !_ignoredWarningCodes.contains(d.diagnosticCode.lowerCaseName);
}

Map<String, String> _buildSymbolToCaseIdMap(List<CodegenCase> cases) {
  final map = <String, String>{};
  for (final c in cases) {
    map[c.id] = c.id;
    for (final sym in _extractDeclaredSymbols(c.declarations)) {
      map[sym] = c.id;
    }
  }
  return map;
}

final RegExp _topLevelDeclNameRe = RegExp(
  r'\b(?:class|enum|mixin|typedef|extension\s+type)\s+([A-Za-z_$][A-Za-z0-9_$]*)',
);

List<String> _extractDeclaredSymbols(String declarations) => [
  for (final m in _topLevelDeclNameRe.allMatches(declarations)) m.group(1)!,
];

String? _attributeOffsetInBatch(String batchSource, int offset) {
  final safeOffset = offset.clamp(0, batchSource.length);
  final prefix = batchSource.substring(0, safeOffset);
  final matches = RegExp(r'// === CASE_START: (\S+) ===').allMatches(prefix);
  if (matches.isEmpty) return null;
  return matches.last.group(1);
}

String? _attributeDiagnosticBySymbol(
  String text,
  Map<String, String> symbolMap,
) {
  String? bestCaseId;
  var bestLen = 0;
  for (final MapEntry(:key, :value) in symbolMap.entries) {
    if (key.length > bestLen && text.contains(key)) {
      bestLen = key.length;
      bestCaseId = value;
    }
  }
  return bestCaseId;
}

String? _attributeDiagnosticInPart(
  String partSource,
  Diagnostic d,
  Map<String, String> symbolMap,
) {
  final fromMsg = _attributeDiagnosticBySymbol(d.message, symbolMap);
  if (fromMsg != null) return fromMsg;
  final clamped = d.offset.clamp(0, partSource.length);
  String? bestCaseId;
  var bestIndex = -1;
  var bestLen = 0;
  for (final MapEntry(:key, :value) in symbolMap.entries) {
    final idx = partSource.lastIndexOf(key, clamped);
    if (idx > bestIndex || (idx == bestIndex && key.length > bestLen)) {
      bestIndex = idx;
      bestLen = key.length;
      bestCaseId = value;
    }
  }
  return bestIndex >= 0 ? bestCaseId : null;
}

String? _extractCaseGeneratedSnippet(String partSource, CodegenCase c) {
  final symbols = _extractDeclaredSymbols(c.declarations);
  if (symbols.isEmpty) return null;
  final patterns = [
    for (final sym in symbols)
      RegExp(r'(?:\b|_\$)' + RegExp.escape(sym) + r'(?:\b|(?=[A-Z]))'),
  ];
  final paragraphs = partSource.split('\n\n');
  final matched = [
    for (final block in paragraphs)
      if (patterns.any((re) => re.hasMatch(block))) block.trim(),
  ];
  return matched.isEmpty ? null : matched.join('\n\n');
}

Future<void> _runBatchedIsolateChecks({
  required AnalysisContext context,
  required String workDir,
  required Uri packageConfigUri,
  required List<CodegenCase> survivors,
  required String generatedPartBody,
  required List<String> imports,
  required Duration isolateTimeout,
  required List<CodegenIssue> issues,
}) async {
  var runnable = [
    for (final c in survivors)
      if (c.runtimeCheck != null && c.runtimeCheck!.trim().isNotEmpty) c,
  ];
  if (runnable.isEmpty) return;

  final mainPath = p.join(workDir, 'fuzz_batch_main.dart');
  final partSource = _formatPartSource(generatedPartBody);
  runnable = await _filterCompilableRuntimeChecks(
    context: context,
    mainPath: mainPath,
    partSource: partSource,
    runnable: runnable,
    imports: imports,
    issues: issues,
  );
  if (runnable.isEmpty) return;

  final failures = await _executeIsolateRunner(
    mainUri: p.toUri(mainPath),
    packageConfigUri: packageConfigUri,
    timeout: isolateTimeout,
  );
  final caseMap = {for (final c in runnable) c.id: c};
  for (final failure in failures) {
    final c = caseMap[failure['id']!];
    if (c == null) continue;
    issues.add((
      caseId: c.id,
      kind: CodegenIssueKind.runtimeFailure,
      message: failure['error']!,
      declarations: c.declarations,
      generatedCode: _extractCaseGeneratedSnippet(partSource, c),
    ));
  }
}

Future<List<CodegenCase>> _filterCompilableRuntimeChecks({
  required AnalysisContext context,
  required String mainPath,
  required String partSource,
  required List<CodegenCase> runnable,
  required List<String> imports,
  required List<CodegenIssue> issues,
}) async {
  final mainSource = _buildRuntimeRunnerSource(
    runnable: runnable,
    imports: imports,
  );
  File(mainPath).writeAsStringSync(mainSource);
  context.changeFile(mainPath);
  await context.applyPendingFileChanges();
  final mainDiag = await _collectRelevantDiagnostics(
    context,
    mainPath,
    includeWarnings: false,
  );
  if (mainDiag.isEmpty) return runnable;

  final caseMap = {for (final c in runnable) c.id: c};
  final symbolMap = _buildSymbolToCaseIdMap(runnable);
  final attr = _attributeDiagnosticList(
    diagnostics: mainDiag,
    fileLabel: 'fuzz_batch_main.dart',
    partSource: partSource,
    caseMap: caseMap,
    resolveCaseId: (d) =>
        _attributeOffsetInBatch(mainSource, d.offset) ??
        _attributeDiagnosticBySymbol(d.message, symbolMap),
  );
  for (final issue in attr.issues) {
    _appendUniqueIssue(issues, issue);
  }
  if (attr.hasUnattributedHardError && attr.errorCaseIds.isEmpty) {
    return const [];
  }
  final cleanRunnable = [
    for (final c in runnable)
      if (!attr.errorCaseIds.contains(c.id)) c,
  ];
  if (cleanRunnable.isNotEmpty) {
    File(mainPath).writeAsStringSync(
      _buildRuntimeRunnerSource(runnable: cleanRunnable, imports: imports),
    );
  }
  return cleanRunnable;
}

Future<List<Map<String, String>>> _executeIsolateRunner({
  required Uri mainUri,
  required Uri packageConfigUri,
  required Duration timeout,
}) async {
  final receivePort = ReceivePort();
  final errorPort = ReceivePort();
  final completer = Completer<List<Map<String, String>>>();
  final sub = receivePort.listen((Object? message) {
    if (message is List && !completer.isCompleted) {
      completer.complete([
        for (final item in message.cast<Map<Object?, Object?>>())
          {'id': item['id'] as String, 'error': item['error'] as String},
      ]);
    }
  });
  final errSub = errorPort.listen((Object? err) {
    if (!completer.isCompleted) {
      completer.completeError(StateError('Isolate crashed: $err'));
    }
  });
  try {
    await Isolate.spawnUri(
      mainUri,
      const <String>[],
      receivePort.sendPort,
      packageConfig: packageConfigUri,
      onError: errorPort.sendPort,
    );
    return await completer.future.timeout(timeout);
  } on IsolateSpawnException {
    return const [];
  } finally {
    await sub.cancel();
    await errSub.cancel();
    receivePort.close();
    errorPort.close();
  }
}

String _buildRuntimeRunnerSource({
  required List<CodegenCase> runnable,
  required List<String> imports,
}) {
  final buf = StringBuffer()
    ..writeln('// ignore_for_file: type=lint')
    ..writeln("import 'dart:isolate';")
    ..writeln("import 'fuzz_batch.dart';");
  for (final imp in imports) {
    final trimmed = imp.trim();
    if (trimmed.isEmpty) continue;
    buf.writeln(trimmed.endsWith(';') ? trimmed : '$trimmed;');
  }
  buf.writeln();
  for (var i = 0; i < runnable.length; i++) {
    final c = runnable[i];
    buf
      ..writeln('// === CASE_START: ${c.id} ===')
      ..writeln('Future<void> _runCase$i() async {')
      ..writeln(c.runtimeCheck)
      ..writeln('}')
      ..writeln('// === CASE_END: ${c.id} ===')
      ..writeln();
  }
  buf
    ..writeln(
      'Future<void> main(List<String> args, SendPort replyPort) async {',
    )
    ..writeln('  final failures = <Map<String, String>>[];');
  for (var i = 0; i < runnable.length; i++) {
    final escapedId = jsonEncode(runnable[i].id);
    buf
      ..writeln('  try {')
      ..writeln('    await _runCase$i();')
      ..writeln('  } on Object catch (e, st) {')
      ..writeln("    failures.add({'id': $escapedId, 'error': '\$e\\n\$st'});")
      ..writeln('  }');
  }
  buf
    ..writeln('  replyPort.send(failures);')
    ..writeln('}');
  return buf.toString();
}

String _buildLibrarySource({
  required List<CodegenCase> cases,
  required List<String> imports,
  required String preamble,
  required bool includePartDirective,
}) {
  final buf = StringBuffer()..writeln('// ignore_for_file: type=lint');
  for (final imp in imports) {
    final trimmed = imp.trim();
    if (trimmed.isEmpty) continue;
    buf.writeln(trimmed.endsWith(';') ? trimmed : '$trimmed;');
  }
  if (includePartDirective) {
    buf.writeln("part 'fuzz_batch.g.dart';");
  }
  if (preamble.trim().isNotEmpty) {
    buf
      ..writeln()
      ..writeln(preamble.trim());
  }
  for (final c in cases) {
    buf
      ..writeln()
      ..writeln('// === CASE_START: ${c.id} ===')
      ..writeln(c.declarations.trim())
      ..writeln('// === CASE_END: ${c.id} ===');
  }
  return buf.toString();
}

String _formatPartSource(String generatedPartBody) {
  final trimmed = generatedPartBody.trim();
  if (trimmed.startsWith('part of ')) {
    return '// ignore_for_file: type=lint\n$trimmed\n';
  }
  return "// ignore_for_file: type=lint\npart of 'fuzz_batch.dart';\n\n$trimmed\n";
}

Future<LibraryElement> _resolveLibraryAtPath(
  AnalysisContext context,
  String filePath,
  String source,
) async {
  File(filePath).writeAsStringSync(source);
  context.changeFile(filePath);
  await context.applyPendingFileChanges();
  final resolved = await context.currentSession.getResolvedLibrary(filePath);
  if (resolved is! ResolvedLibraryResult) {
    throw StateError('Failed to resolve library at $filePath: $resolved');
  }
  return resolved.element;
}

/// Formats a [CodegenBatchReport] into a human-readable diagnostic summary.
String formatCodegenBatchReport(CodegenBatchReport report) {
  final buf = StringBuffer()
    ..writeln(
      'Codegen batch verification found ${report.issues.length} issue(s) '
      '(${report.passedCases}/${report.totalCases} cases passed):',
    );
  for (final issue in report.issues) {
    buf
      ..writeln()
      ..writeln('--- [${issue.kind.name}] Case: ${issue.caseId} ---')
      ..writeln('Message: ${issue.message.trim()}')
      ..writeln('Declarations:\n${issue.declarations.trim()}');
    if (issue.generatedCode != null && issue.generatedCode!.trim().isNotEmpty) {
      buf.writeln('Generated Code:\n${issue.generatedCode!.trim()}');
    }
  }
  return buf.toString();
}

/// Locates `.dart_tool/package_config.json` starting at [startDir] and walking
/// up parent directories (supporting Dart pub workspaces).
File findPackageConfigFile(String startDir) {
  var current = p.normalize(p.absolute(startDir));
  while (true) {
    final candidate = File(
      p.join(current, '.dart_tool', 'package_config.json'),
    );
    if (candidate.existsSync()) return candidate;
    final parent = p.dirname(current);
    if (parent == current) break;
    current = parent;
  }
  throw StateError(
    'No .dart_tool/package_config.json found in $startDir or its parents. '
    'Run `dart pub get` first.',
  );
}

/// Prepares a merged `package_config.json` inside `<packageRoot>/.dart_tool/fuzz/`
/// that includes all dependencies from `<packageRoot>` plus `package:fuzz`,
/// enabling zero-dependency codegen fuzz scripts (`fuzz codegen <script.dart>`)
/// to import both the target package and `package:fuzz/fuzz.dart`.
Future<String> prepareCodegenPackageConfig({
  required String packageRoot,
  String? workDir,
}) async {
  final absPkgRoot = p.normalize(p.absolute(packageRoot));
  final baseConfigFile = findPackageConfigFile(absPkgRoot);
  final baseConfigDir = p.dirname(baseConfigFile.path);
  final raw =
      jsonDecode(baseConfigFile.readAsStringSync()) as Map<String, Object?>;
  final rawPackages = (raw['packages'] as List<Object?>)
      .cast<Map<String, Object?>>();

  final updatedPackages = <Map<String, Object?>>[];
  final presentNames = <String>{};
  for (final entry in rawPackages) {
    final name = entry['name'] as String;
    presentNames.add(name);
    updatedPackages.add(_absolutizeEntry(entry, baseConfigDir));
  }

  for (final pkgName in const [
    'fuzz',
    'analyzer',
    'cli_util',
    'path',
    'stack_trace',
  ]) {
    if (presentNames.contains(pkgName)) continue;
    final resolved = await Isolate.resolvePackageUri(
      Uri.parse('package:$pkgName/$pkgName.dart'),
    );
    if (resolved == null) continue;
    final pkgRootDir = p.dirname(p.dirname(resolved.toFilePath()));
    updatedPackages.add({
      'name': pkgName,
      'rootUri': p.toUri(pkgRootDir).toString(),
      'packageUri': 'lib/',
      'languageVersion': '3.11',
    });
  }

  final outDir = workDir != null && workDir.isNotEmpty
      ? p.normalize(p.absolute(workDir))
      : p.join(absPkgRoot, '.dart_tool', 'fuzz');
  Directory(outDir).createSync(recursive: true);
  final outPath = p.join(outDir, 'codegen_package_config.json');
  File(outPath).writeAsStringSync(
    const JsonEncoder.withIndent('  ')
        .convert({...raw, 'packages': updatedPackages}),
  );
  return outPath;
}

Map<String, Object?> _absolutizeEntry(
  Map<String, Object?> entry,
  String configDir,
) {
  final rootUriStr = entry['rootUri'] as String;
  final parsed = Uri.parse(rootUriStr);
  if (parsed.hasScheme) return entry;
  final absPath = p.normalize(p.join(configDir, p.fromUri(parsed)));
  return {...entry, 'rootUri': p.toUri(absPath).toString()};
}
