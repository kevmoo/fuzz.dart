@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:checks/checks.dart';
import 'package:fuzz/src/fuzz_runtime.dart';
import 'package:fuzz/src/native_builder.dart';
import 'package:test/test.dart';
import 'package:test_descriptor/test_descriptor.dart' as d;

void main() {
  group('NativeFuzzerBuilder', () {
    test('embeddedFuzzerCc stays in sync with lib/src/native/fuzzer.cc and '
        'materializes fallback file', () async {
      final onDisk = File('lib/src/native/fuzzer.cc').readAsStringSync().trim();
      check(NativeFuzzerBuilder.embeddedFuzzerCc.trim()).equals(onDisk);

      final resolved = await NativeFuzzerBuilder.resolveFuzzerCcPath(
        fallbackOutputDir: d.sandbox,
      );
      check(File(resolved).existsSync()).isTrue();
    });

    test('fails hard with ToolchainMissingException and pure-dart hint when '
        'clang++ is missing', () async {
      check(
        NativeFuzzerBuilder.findClangExecutable(
          environment: {'CLANG_CXX': '/nonexistent/clang++'},
        ),
      ).isNull();

      await check(
        NativeFuzzerBuilder.buildSharedLibrary(
          outputDir: d.sandbox,
          clangExecutable: '/nonexistent/clang++',
        ),
      ).throws<ToolchainMissingException>(
        (it) => it.has((e) => e.toString(), 'message')
          ..contains('--mode=cgf')
          ..contains('--mode=pure-dart')
          ..contains('clang')
          ..contains('libclang-rt-dev'),
      );
    });
  });

  group('FuzzRuntime (Pure-Dart Mode)', () {
    test('records edge and comparison feedback and drives pure-Dart mutator '
        'including LHS constants and List<int> equality', () {
      FuzzRuntime.init(mode: FuzzMode.pureDart);
      $fuzzCovMap.fillRange(0, FuzzRuntime.numCounters, 0);
      $fuzzPrevLoc = 0;

      $fuzzEdge(101);
      check($fuzzEq(1000, 1000, 202)).isTrue();
      check($fuzzNe('alpha', 'beta', 303)).isTrue();
      check($fuzzLt(0, 4, 404)).isTrue();
      check($fuzzLe(4, 4, 405)).isTrue();
      check($fuzzGt(9, 4, 406)).isTrue();
      check($fuzzGe(9, 9, 407)).isTrue();
      check($fuzzXor(0x41, 0x61, 505)).equals(0x20);
      check($fuzzSwitch('hdr', <Object?>['hdr', 'body'], 606)).equals('hdr');
      check($fuzzExpr(707, 'payload')).equals('payload');
      check($fuzzSiteHits[707]).equals(1);

      $fuzzSiteHits[808] = 0;
      check($fuzzBool(true, 808)).isTrue();
      check($fuzzSiteHits[808]).equals(1);
      check($fuzzBool(false, 808)).isFalse();
      check($fuzzSiteHits[808]).equals(3);

      final nonZero = $fuzzCovMap.where((b) => b != 0).length;
      check(nonZero).isGreaterOrEqual(8);

      var foundRhsMagic = false;
      var foundLhsMagic = false;
      expect(
        () => FuzzRuntime.runDriver(
          (Uint8List data) {
            $fuzzEdge(1);
            if ($fuzzGe(data.length, 4, 10)) {
              $fuzzEdge(2);
              final str = String.fromCharCodes(data.take(4));
              if ($fuzzEq(str, 'FUZZ', 20)) {
                foundRhsMagic = true;
              }
              if ($fuzzEq('DART', str, 30)) {
                foundLhsMagic = true;
              }
            }
          },
          mode: FuzzMode.pureDart,
          fuzzerArgs: const ['-runs=3000', '-max_len=16'],
        ),
        prints(
          allOf(
            startsWith('INFO: Seed: '),
            contains('#1\tINITED\t'),
            contains('#3000\tDONE\t'),
          ),
        ),
      );
      check(foundRhsMagic).isTrue();
      check(foundLhsMagic).isTrue();
    });

    test('respects -seed, persists new inputs to corpus dir, and omits '
        'unconditional hex boundary seeds', () {
      final corpusDir = d.dir('pure_corpus');
      final corpusPath = '${d.sandbox}/pure_corpus';
      Directory(corpusPath).createSync(recursive: true);

      final seenRun1 = <List<int>>[];
      expect(
        () => FuzzRuntime.runDriver(
          (Uint8List data) {
            seenRun1.add(data.toList());
            $fuzzEdge(data.isEmpty ? 1 : (data.first + 2));
          },
          mode: FuzzMode.pureDart,
          fuzzerArgs: ['-runs=15', '-seed=42', corpusPath],
        ),
        prints(
          allOf(
            startsWith('INFO: Seed: 42\n#1\tINITED\t'),
            contains('#15\tDONE\t'),
          ),
        ),
      );

      // First input in an empty corpus must be the 0-byte seed, without
      // injecting CRLF hex strings when no seed files exist.
      check(seenRun1.first).isEmpty();
      check(seenRun1.map(String.fromCharCodes))
          .not((it) => it.contains('7fffffffffffffff\r\n'));

      // Newly discovered coverage-increasing inputs must be persisted to
      // corpusPath.
      final persistedFiles = Directory(corpusPath)
          .listSync()
          .whereType<File>()
          .toList();
      check(persistedFiles).isNotEmpty();

      // Re-running with the same -seed against a fresh directory must explore
      // the exact same sequence of inputs.
      final corpusPath2 = '${d.sandbox}/pure_corpus_2';
      Directory(corpusPath2).createSync(recursive: true);
      final seenRun2 = <List<int>>[];
      expect(
        () => FuzzRuntime.runDriver(
          (Uint8List data) {
            seenRun2.add(data.toList());
            $fuzzEdge(data.isEmpty ? 1 : (data.first + 2));
          },
          mode: FuzzMode.pureDart,
          fuzzerArgs: ['-runs=15', '-seed=42', corpusPath2],
        ),
        prints(
          allOf(
            startsWith('INFO: Seed: 42\n#1\tINITED\t'),
            contains('#15\tDONE\t'),
          ),
        ),
      );
      check(seenRun2).deepEquals(seenRun1);
      check(corpusDir.name).equals('pure_corpus');
    });

    test('writes crash-<hash> reproducer file on unhandled exception with '
        '-artifact_prefix and -exact_artifact_path', () async {
      final scriptFile = File('${d.sandbox}/crash_harness.dart')
        ..writeAsStringSync('''
import 'dart:typed_data';
import 'package:fuzz/src/fuzz_runtime.dart';

void main(List<String> args) {
  FuzzRuntime.runDriver(
    (Uint8List data) {
      throw StateError('synthetic parser crash');
    },
    mode: FuzzMode.pureDart,
    fuzzerArgs: args,
  );
}
''');

      final pkgConfig =
          '${Directory.current.path}/.dart_tool/package_config.json';
      final artifactsDir = Directory('${d.sandbox}/artifacts')
        ..createSync(recursive: true);
      final prefixRes = await Process.run(Platform.resolvedExecutable, [
        '--packages=$pkgConfig',
        scriptFile.path,
        '-runs=5',
        '-artifact_prefix=${artifactsDir.path}/',
      ]);
      check(prefixRes.exitCode, because: '${prefixRes.stderr}').equals(77);
      check(prefixRes.stderr as String).contains('Test unit written to');
      final writtenFiles = artifactsDir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.contains('crash-'))
          .toList();
      check(writtenFiles).length.equals(1);

      final exactPath = '${d.sandbox}/artifacts/exact_repro.bin';
      final exactRes = await Process.run(Platform.resolvedExecutable, [
        '--packages=$pkgConfig',
        scriptFile.path,
        '-runs=5',
        '-exact_artifact_path=$exactPath',
      ]);
      check(exactRes.exitCode, because: '${exactRes.stderr}').equals(77);
      check(File(exactPath).existsSync()).isTrue();
    });

    test('loads -dict=<path> tokens in Pure-Dart mode and discovers '
        'multi-byte magic sequence', () {
      final dictFile = File('${d.sandbox}/custom.dict')
        ..writeAsStringSync('# comment line\nkw1="<<FUZZ_DICT_MAGIC>>"\n');
      var matchedMagic = false;
      expect(
        () => FuzzRuntime.runDriver(
          (Uint8List data) {
            final str = String.fromCharCodes(data);
            if (str.contains('<<FUZZ_DICT_MAGIC>>')) {
              matchedMagic = true;
              $fuzzEdge(500);
            } else {
              $fuzzEdge(1);
            }
          },
          mode: FuzzMode.pureDart,
          fuzzerArgs: ['-runs=80', '-seed=7', '-dict=${dictFile.path}'],
        ),
        prints(
          allOf(
            startsWith('INFO: Seed: 7\n#1\tINITED\t'),
            contains('#80\tDONE\t'),
          ),
        ),
      );
      check(matchedMagic).isTrue();
    });

    test('drives async Future/Stream targets synchronously per input, '
        'recording post-await coverage and catching '
        'uncompleted Completers', () async {
      FuzzRuntime.init(mode: FuzzMode.pureDart);
      $fuzzSiteHits[301] = 0;

      var solvedPostAwaitMagic = false;
      var unawaitedPostCancelRan = false;
      expect(
        () => FuzzRuntime.runDriver(
          (Uint8List data) async {
            final sub = Stream<Uint8List>.value(data).listen((_) {});
            await sub.cancel();
            final emptyIter = StreamIterator(const Stream<int>.empty());
            while (await emptyIter.moveNext()) {}
            await emptyIter.cancel();
            await Future<void>.delayed(const Duration(milliseconds: 10));
            final chunks = await Stream<Uint8List>.value(data).toList();
            final merged = chunks.isEmpty ? Uint8List(0) : chunks.first;
            $fuzzEdge(301);
            if ($fuzzGe(merged.length, 4, 302)) {
              final str = String.fromCharCodes(merged.take(4));
              if ($fuzzEq(str, 'ASYN', 303)) {
                solvedPostAwaitMagic = true;
              }
            }
            unawaited(() async {
              final s = Stream<int>.value(1).listen((_) {});
              await s.cancel();
              unawaitedPostCancelRan = true;
            }());
          },
          mode: FuzzMode.pureDart,
          fuzzerArgs: const ['-runs=1500', '-max_len=16'],
        ),
        prints(
          allOf(
            startsWith('INFO: Seed: '),
            contains('#1\tINITED\t'),
            contains('#1500\tDONE\t'),
          ),
        ),
      );
      check($fuzzSiteHits[301]).equals(1);
      check(solvedPostAwaitMagic).isTrue();
      check(unawaitedPostCancelRan).isTrue();

      // An async target that awaits an uncompleted Completer (without a timer)
      // must fail deterministically with exitCode 77 rather than silently
      // succeeding.
      final artifactsDir = Directory('${d.sandbox}/stalled_async')
        ..createSync(recursive: true);
      final stalledScript = File('${d.sandbox}/stalled_harness.dart')
        ..writeAsStringSync('''
import 'dart:async';
import 'dart:typed_data';
import 'package:fuzz/src/fuzz_runtime.dart';

void main(List<String> args) {
  FuzzRuntime.runDriver(
    (Uint8List data) async {
      await Completer<void>().future;
    },
    mode: FuzzMode.pureDart,
    fuzzerArgs: args,
  );
}
''');
      final pkgConfig =
          '${Directory.current.path}/.dart_tool/package_config.json';
      final stalledRes = await Process.run(Platform.resolvedExecutable, [
        '--packages=$pkgConfig',
        stalledScript.path,
        '-runs=1',
        '-artifact_prefix=${artifactsDir.path}/',
      ]);
      check(stalledRes.exitCode, because: '${stalledRes.stderr}').equals(77);
      check(
        stalledRes.stderr as String,
      ).contains('Async fuzzTarget did not complete after draining microtasks');
      final stalledCrashes = artifactsDir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.contains('crash-'))
          .toList();
      check(stalledCrashes).length.equals(1);
    });
  });

  group('FuzzRuntime (Native CGF Mode)', () {
    test('compiles fuzzer.cc, links libFuzzer counters, and solves List<int> '
        'comparisons when clang++ is available', () async {
      final clang = NativeFuzzerBuilder.findClangExecutable();
      if (clang == null) {
        markTestSkipped('clang++ not installed on this runner');
        return;
      }

      final libPath = await NativeFuzzerBuilder.buildSharedLibrary(
        outputDir: d.sandbox,
        clangExecutable: clang,
      );
      FuzzRuntime.init(mode: FuzzMode.cgf, libraryPath: libPath);
      $fuzzCovMap.fillRange(0, FuzzRuntime.numCounters, 0);
      $fuzzPrevLoc = 0;

      $fuzzEdge(77);
      check($fuzzEq(0xCAFEBABE, 0xCAFEBABE, 88)).isTrue();
      check($fuzzEq('magic', 'magic', 99)).isTrue();
      check($fuzzEq(const [0x46, 0x55], const [0x46, 0x5A], 100)).isFalse();
      check($fuzzCovMap.where((b) => b != 0).length).isGreaterOrEqual(4);

      // Verify switching to pureDart and back to cgf preserves native siteHits
      // buffer identity.
      final nativeSiteHitsRef = $fuzzSiteHits;
      FuzzRuntime.init(mode: FuzzMode.pureDart);
      check($fuzzSiteHits).identicalTo(nativeSiteHitsRef);
      FuzzRuntime.init(mode: FuzzMode.cgf, libraryPath: libPath);
      check($fuzzSiteHits).identicalTo(nativeSiteHitsRef);
    });

    test('exits with code 77 and prints DEDUPLICATED CRASH SUMMARY when '
        'FuzzRuntime.runDriver is called directly in FuzzMode.cgf (including '
        'async Stream targets and unawaited microtask errors)', () async {
      final clang = NativeFuzzerBuilder.findClangExecutable();
      if (clang == null) {
        markTestSkipped('clang++ not installed on this runner');
        return;
      }

      final libPath = await NativeFuzzerBuilder.buildSharedLibrary(
        outputDir: d.sandbox,
        clangExecutable: clang,
      );
      final artifactsDir = Directory('${d.sandbox}/cgf_crashes')
        ..createSync(recursive: true);
      final siteHitsPath = '${d.sandbox}/cgf_site_hits.bin';
      final scriptFile = File('${d.sandbox}/cgf_crash_harness.dart')
        ..writeAsStringSync('''
import 'dart:async';
import 'dart:typed_data';
import 'package:fuzz/fuzz.dart';
import 'package:fuzz/src/fuzz_runtime.dart';

void main(List<String> args) {
  FuzzRuntime.runDriver(
    (Uint8List data) async {
      \$fuzzEdge(42);
      final items = await Stream<Uint8List>.value(data).toList();
      \$fuzzEdge(43);
      // Allocate external-sized TypedData buffers to exercise VM heap state
      // prior to libFuzzer's C std::exit(0) teardown.
      final scratch = Uint8List(65536);
      final payload = items.first;
      scratch[0] = payload.isEmpty ? 1 : payload[0];
      if (payload.isEmpty) {
        throw StateError('empty async input crash \${scratch[0]}');
      }
      unawaited(
        Future<void>.microtask(() {
          throw ArgumentError('unawaited microtask crash \${scratch[0]}');
        }),
      );
    },
    mode: FuzzMode.cgf,
    libraryPath: r'$libPath',
    fuzzerArgs: args,
  );
}
''');

      final pkgConfig =
          '${Directory.current.path}/.dart_tool/package_config.json';
      final result = await Process.run(
        Platform.resolvedExecutable,
        [
          '--packages=$pkgConfig',
          scriptFile.path,
          '-runs=25',
          '-artifact_prefix=${artifactsDir.path}/',
        ],
        environment: {'FUZZ_SITE_HITS_PATH': siteHitsPath},
      );
      check(result.exitCode, because: '${result.stderr}').equals(77);
      final stderrStr = result.stderr as String;
      check(stderrStr).not((it) => it.contains('unreachable code'));
      check(stderrStr).contains('DEDUPLICATED CRASH SUMMARY');
      check(stderrStr).contains('StateError');
      check(stderrStr).contains('ArgumentError');
      final crashFiles = artifactsDir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.contains('crash-'))
          .toList();
      check(crashFiles).length.equals(2);

      // Verify C++ FlushSiteHitsAtExit flushed FUZZ_SITE_HITS_PATH including
      // post-await edge 43 without re-entering the Dart VM during std::atexit.
      final siteHitsBytes = File(siteHitsPath).readAsBytesSync();
      check(siteHitsBytes).length.equals(FuzzRuntime.numCounters);
      check(siteHitsBytes[42]).equals(1);
      check(siteHitsBytes[43]).equals(1);
    });
  });
}
