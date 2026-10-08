import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:cli_util/cli_util.dart';
import 'package:fuzz/src/coverage_report.dart';
import 'package:fuzz/src/instrument_ast.dart';
import 'package:fuzz/src/native_builder.dart';
import 'package:path/path.dart' as p;

Future<void> main(List<String> args) async {
  final runner =
      CommandRunner<int>(
          'fuzz',
          'Coverage-guided libFuzzer + dart:ffi AST instrumentor and pure-Dart '
              'parser fuzzing tool.',
        )
        ..addCommand(_InstrumentCommand())
        ..addCommand(_RunCommand());

  try {
    final code = await runner.run(args);
    exitCode = code ?? 0;
  } on UsageException catch (e) {
    stderr.writeln(e);
    exitCode = 64;
  } on ToolchainMissingException catch (e) {
    stderr.writeln(e);
    exitCode = 69;
  } on Object catch (e) {
    stderr.writeln('ERROR: $e');
    exitCode = 1;
  }
}

class _InstrumentCommand extends Command<int> {
  @override
  String get name => 'instrument';

  @override
  String get description =>
      'Instruments a file or a package lib/ directory into .dart_tool/fuzz/.';

  _InstrumentCommand() {
    argParser
      ..addOption(
        'package-root',
        help: 'Path to the target package root directory.',
        defaultsTo: '.',
      )
      ..addOption(
        'work-dir',
        help:
            'Directory for instrumented overlay and manifest (defaults to '
            '<package-root>/.dart_tool/fuzz).',
      )
      ..addMultiOption(
        'instrument-packages',
        help:
            'Additional dependency packages from package_config.json to '
            'AST-instrument (e.g. yaml,source_span).',
      )
      ..addOption(
        'input',
        help: 'Single .dart source file to instrument (optional).',
      )
      ..addOption(
        'output',
        help: 'Output file path when --input is specified.',
      );
  }

  @override
  Future<int> run() async {
    final opts = argResults!;
    final input = opts['input'] as String?;
    final output = opts['output'] as String?;

    if (input != null) {
      if (output == null) {
        usageException('--output is required when --input is provided.');
      }
      final source = File(input).readAsStringSync();
      final instrumentor = AstInstrumentor();
      final out = instrumentor.instrumentSource(source);
      File(output).writeAsStringSync(out);
      stdout.writeln(
        'Instrumented $input -> $output '
        '(edges: ${instrumentor.edgesInserted}, '
        'compares: ${instrumentor.comparesInserted}, '
        'switches: ${instrumentor.switchesInserted})',
      );
      return 0;
    }

    final pkgRoot = opts['package-root'] as String;
    final workDir = opts['work-dir'] as String?;
    final additionalPackages = opts['instrument-packages'] as List<String>;
    final res = await PackageOverlayInstrumentor.instrumentPackage(
      packageRoot: pkgRoot,
      workDir: workDir,
      additionalPackages: additionalPackages,
    );
    stdout.writeln(
      'Instrumented package:${res.packageName} '
      '(${res.filesInstrumented} files -> ${res.instrumentedLibDir}; '
      'edges: ${res.edgesInserted}, compares: ${res.comparesInserted}, '
      'switches: ${res.switchesInserted}, '
      'dict tokens: ${res.dictionaryTokensExtracted})\n'
      'Overlay config: ${res.overlayPackageConfigPath}',
    );
    return 0;
  }
}

class _RunCommand extends Command<int> {
  @override
  String get name => 'run';

  @override
  String get description =>
      'Instruments the target package and runs a fuzz target harness.';

  @override
  String get invocation =>
      '${runner!.executableName} $name [arguments] <target.dart> '
      '[corpus_or_fuzzer_args...]';

  _RunCommand() {
    argParser
      ..addOption(
        'package-root',
        help: 'Target package directory whose lib/ will be instrumented.',
        defaultsTo: '.',
      )
      ..addOption(
        'work-dir',
        help:
            'Directory for instrumented overlay and coverage artifacts '
            '(defaults to <package-root>/.dart_tool/fuzz).',
      )
      ..addMultiOption(
        'instrument-packages',
        help:
            'Additional dependency packages from package_config.json to '
            'AST-instrument (e.g. yaml,source_span).',
      )
      ..addOption(
        'dict',
        help:
            'Optional path to an AFL/libFuzzer dictionary file (-dict=<path>).',
      )
      ..addFlag(
        'auto-dict',
        help:
            'Automatically seed the fuzzer dictionary with string/char '
            'literals harvested from the instrumented AST.',
        defaultsTo: true,
      )
      ..addOption(
        'mode',
        help: 'Fuzzing execution mode.',
        allowed: const ['cgf', 'pure-dart'],
        defaultsTo: 'cgf',
      )
      ..addOption(
        'runs',
        help: 'Maximum number of fuzzing iterations (-runs=<N>).',
        defaultsTo: '200000',
      )
      ..addOption(
        'max-len',
        help: 'Maximum input length in bytes (-max_len=<N>).',
        defaultsTo: '4096',
      )
      ..addOption(
        'max-total-time',
        help: 'Maximum total fuzzing time in seconds (-max_total_time=<S>).',
        defaultsTo: '0',
      )
      ..addOption(
        'rss-limit-mb',
        help: 'Process RSS memory ceiling in MB (-rss_limit_mb=<MB>).',
        defaultsTo: '2048',
      )
      ..addOption(
        'heap-limit-mb',
        help: 'Dart VM old-generation heap ceiling in MB.',
        defaultsTo: '1024',
      )
      ..addOption(
        'timeout',
        help: 'Per-input timeout in seconds (-timeout=<S>).',
        defaultsTo: '5',
      );
  }

  @override
  Future<int> run() async {
    final opts = argResults!;
    if (opts.rest.isEmpty || opts.rest.first.startsWith('-')) {
      usageException('Missing required positional argument: <target.dart>.');
    }
    final rawTarget = opts.rest.first;

    final pkgRoot = p.normalize(p.absolute(opts['package-root'] as String));
    final rawWorkDir = opts['work-dir'] as String?;
    final fuzzDir = rawWorkDir != null && rawWorkDir.isNotEmpty
        ? p.normalize(p.absolute(rawWorkDir))
        : p.join(pkgRoot, '.dart_tool', 'fuzz');
    final additionalPackages = opts['instrument-packages'] as List<String>;
    final targetPath = _resolveFileInPackage(
      pkgRoot,
      rawTarget,
      label: 'Target script',
    );
    final modeStr = opts['mode'] as String;

    final overlay = await PackageOverlayInstrumentor.instrumentPackage(
      packageRoot: pkgRoot,
      workDir: fuzzDir,
      additionalPackages: additionalPackages,
    );
    stdout.writeln(
      'Prepared AST overlay for package:${overlay.packageName} '
      '(${overlay.filesInstrumented} files, ${overlay.edgesInserted} edges, '
      '${overlay.comparesInserted} compares, '
      '${overlay.switchesInserted} switches, '
      '${overlay.dictionaryTokensExtracted} dict tokens).',
    );

    final siteHitsPath = p.join(fuzzDir, 'site_hits.bin');
    final siteHitsFile = File(siteHitsPath);
    if (siteHitsFile.existsSync()) {
      siteHitsFile.deleteSync();
    }

    final libPath = modeStr == 'pure-dart'
        ? null
        : await NativeFuzzerBuilder.buildSharedLibrary(outputDir: fuzzDir);
    final resolvedDictPath = _resolveDictionaryPath(
      pkgRoot,
      overlay.dictionaryTokensExtracted > 0 ? overlay.dictionaryPath : null,
      opts,
    );

    final heapLimitMb = opts['heap-limit-mb'] as String;
    final fuzzerFlags = _prepareFuzzerFlags(
      opts: opts,
      pkgRoot: pkgRoot,
      fuzzDir: fuzzDir,
      resolvedDictPath: resolvedDictPath,
    );

    final dartBin =
        dartExecutable ??
        (throw StateError('Could not locate the `dart` executable.'));
    final entrypointPath = _prepareRunnerEntrypoint(
      targetPath: targetPath,
      fuzzDir: fuzzDir,
    );
    final proc = await Process.start(
      dartBin,
      [
        '--enable-asserts',
        '--old_gen_heap_size=$heapLimitMb',
        '--packages=${overlay.overlayPackageConfigPath}',
        entrypointPath,
        ...fuzzerFlags,
      ],
      workingDirectory: pkgRoot,
      environment: {
        ...Platform.environment,
        'FUZZ_MODE': modeStr,
        'FUZZ_SITE_HITS_PATH': siteHitsPath,
        'FUZZ_LIB_PATH': ?libPath,
      },
      mode: ProcessStartMode.inheritStdio,
    );
    final code = await proc.exitCode;
    _emitCoverageSummary(
      fuzzDir: fuzzDir,
      edgeManifestPath: overlay.edgeManifestPath,
      siteHitsFile: siteHitsFile,
    );
    return code;
  }

  List<String> _prepareFuzzerFlags({
    required ArgResults opts,
    required String pkgRoot,
    required String fuzzDir,
    required String? resolvedDictPath,
  }) {
    final restArgs = opts.rest.sublist(1);
    final crashesDir = p.join(fuzzDir, 'crashes');
    Directory(crashesDir).createSync(recursive: true);
    final hasExplicitArtifactFlag = restArgs.any(
      (a) =>
          a.startsWith('-artifact_prefix=') ||
          a.startsWith('-exact_artifact_path='),
    );
    final resolvedRestArgs = [
      for (final arg in restArgs)
        arg.startsWith('-') ? arg : _resolvePositionalArg(pkgRoot, arg),
    ];
    final maxTotalTime = opts['max-total-time'] as String;
    return <String>[
      '-use_value_profile=1',
      '-runs=${opts['runs']}',
      '-max_len=${opts['max-len']}',
      '-rss_limit_mb=${opts['rss-limit-mb']}',
      '-timeout=${opts['timeout']}',
      if (maxTotalTime != '0') '-max_total_time=$maxTotalTime',
      if (resolvedDictPath != null) '-dict=$resolvedDictPath',
      if (!hasExplicitArtifactFlag) '-artifact_prefix=$crashesDir/',
      ...resolvedRestArgs,
    ];
  }

  static const _reproducerPrefixes = [
    'crash-',
    'timeout-',
    'oom-',
    'leak-',
    'slow-unit-',
  ];

  String _resolvePositionalArg(String pkgRoot, String rawPath) {
    final absPath = p.normalize(p.absolute(rawPath));
    if (FileSystemEntity.typeSync(absPath) != FileSystemEntityType.notFound) {
      return absPath;
    }
    final pkgPath = p.normalize(p.join(pkgRoot, rawPath));
    if (FileSystemEntity.typeSync(pkgPath) != FileSystemEntityType.notFound) {
      return pkgPath;
    }
    final base = p.basename(rawPath);
    if (_reproducerPrefixes.any(base.startsWith)) {
      usageException('Reproducer file not found: $pkgPath');
    }
    Directory(pkgPath).createSync(recursive: true);
    return pkgPath;
  }

  static String _prepareRunnerEntrypoint({
    required String targetPath,
    required String fuzzDir,
  }) {
    final targetSource = File(targetPath).readAsStringSync();
    final parsed = parseString(
      content: targetSource,
      throwIfDiagnostics: false,
    );
    final hasMain = parsed.unit.declarations.any(
      (d) => d is FunctionDeclaration && d.name.lexeme == 'main',
    );
    if (hasMain) {
      return targetPath;
    }
    final wrapperPath = p.join(fuzzDir, 'fuzz_entrypoint.dart');
    final targetUri = p.toUri(targetPath);
    File(wrapperPath).writeAsStringSync('''
import 'dart:typed_data';
import 'package:fuzz/fuzz.dart';
import '$targetUri' as target;

void main(List<String> args) {
  FuzzRuntime.runDriver(
    (Uint8List data) {
      target.fuzzTarget(data);
      return 0;
    },
    fuzzerArgs: args,
  );
}
''');
    return wrapperPath;
  }

  String _resolveFileInPackage(
    String pkgRoot,
    String rawPath, {
    required String label,
  }) {
    final absPath = p.normalize(p.absolute(rawPath));
    if (File(absPath).existsSync()) return absPath;
    final pkgRelative = p.normalize(p.join(pkgRoot, rawPath));
    if (File(pkgRelative).existsSync()) return pkgRelative;
    usageException('$label not found: $absPath');
  }

  String? _resolveDictionaryPath(
    String pkgRoot,
    String? autoDictPath,
    ArgResults opts,
  ) {
    final userDict = opts['dict'] as String?;
    final autoDict = opts['auto-dict'] as bool;
    final hasAuto =
        autoDict && autoDictPath != null && File(autoDictPath).existsSync();
    if (userDict == null || userDict.isEmpty) {
      return hasAuto ? autoDictPath : null;
    }
    final userDictFile = _resolveFileInPackage(
      pkgRoot,
      userDict,
      label: 'Dictionary file',
    );
    if (!hasAuto) return userDictFile;
    final mergedPath = p.join(p.dirname(autoDictPath), 'merged.dict');
    final userContent = File(userDictFile).readAsStringSync();
    final autoContent = File(autoDictPath).readAsStringSync();
    File(mergedPath).writeAsStringSync('$userContent\n$autoContent');
    return mergedPath;
  }

  static void _emitCoverageSummary({
    required String fuzzDir,
    required String edgeManifestPath,
    required File siteHitsFile,
  }) {
    final manifestFile = File(edgeManifestPath);
    if (!siteHitsFile.existsSync() || !manifestFile.existsSync()) return;
    final report = computeCoverageReport(
      edgeManifestJson: manifestFile.readAsStringSync(),
      siteHits: siteHitsFile.readAsBytesSync(),
    );
    final reportJsonPath = p.join(fuzzDir, 'coverage_report.json');
    File(reportJsonPath).writeAsStringSync(coverageReportToJson(report));
    stdout
      ..write(formatCoverageTable(report))
      ..writeln('Coverage report written to: $reportJsonPath');
  }
}
