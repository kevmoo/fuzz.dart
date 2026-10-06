@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:fuzz/fuzz.dart';
import 'package:fuzz/src/native_builder.dart';
import 'package:test/test.dart';
import 'package:test_descriptor/test_descriptor.dart' as d;

void main() {
  group('NativeFuzzerBuilder', () {
    test('fails hard with ToolchainMissingException and pure-dart hint when '
        'clang++ is missing', () async {
      expect(
        NativeFuzzerBuilder.findClangExecutable(
          environment: {'CLANG_CXX': '/nonexistent/clang++'},
        ),
        isNull,
      );

      await expectLater(
        () => NativeFuzzerBuilder.buildSharedLibrary(
          outputDir: d.sandbox,
          clangExecutable: '/nonexistent/clang++',
        ),
        throwsA(
          isA<ToolchainMissingException>().having(
            (e) => e.toString(),
            'message',
            allOf(
              contains('--mode=cgf'),
              contains('--mode=pure-dart'),
              contains('clang'),
              contains('libclang-rt-dev'),
            ),
          ),
        ),
      );
    });
  });

  group('FuzzRuntime (Pure-Dart Mode)', () {
    test('records edge and comparison feedback and drives pure-Dart mutator '
        'including LHS constants and List<int> equality', () {
      FuzzRuntime.init(mode: FuzzMode.pureDart);
      FuzzRuntime.covMap.fillRange(0, FuzzRuntime.numCounters, 0);
      FuzzRuntime.prevLoc = 0;

      $fuzzEdge(101);
      expect($fuzzEq(1000, 1000, 202), isTrue);
      expect($fuzzNe('alpha', 'beta', 303), isTrue);
      expect($fuzzLt(0, 4, 404), isTrue);
      expect($fuzzLe(4, 4, 405), isTrue);
      expect($fuzzGt(9, 4, 406), isTrue);
      expect($fuzzGe(9, 9, 407), isTrue);
      expect($fuzzXor(0x41, 0x61, 505), equals(0x20));
      expect($fuzzSwitch('hdr', <Object?>['hdr', 'body'], 606), 'hdr');
      expect($fuzzExpr(707, 'payload'), equals('payload'));
      expect(FuzzRuntime.siteHits[707], equals(1));

      FuzzRuntime.siteHits[808] = 0;
      expect($fuzzBool(true, 808), isTrue);
      expect(FuzzRuntime.siteHits[808], equals(1));
      expect($fuzzBool(false, 808), isFalse);
      expect(FuzzRuntime.siteHits[808], equals(3));

      final nonZero = FuzzRuntime.covMap.where((b) => b != 0).length;
      expect(nonZero, greaterThanOrEqualTo(8));

      var foundRhsMagic = false;
      var foundLhsMagic = false;
      FuzzRuntime.runDriver(
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
          return 0;
        },
        mode: FuzzMode.pureDart,
        fuzzerArgs: const ['-runs=3000', '-max_len=16'],
      );
      expect(foundRhsMagic, isTrue);
      expect(foundLhsMagic, isTrue);
    });

    test('respects -seed, persists new inputs to corpus dir, and omits '
        'unconditional hex boundary seeds', () {
      final corpusDir = d.dir('pure_corpus');
      final corpusPath = '${d.sandbox}/pure_corpus';
      Directory(corpusPath).createSync(recursive: true);

      final seenRun1 = <List<int>>[];
      FuzzRuntime.runDriver(
        (Uint8List data) {
          seenRun1.add(data.toList());
          $fuzzEdge(data.isEmpty ? 1 : (data.first + 2));
          return 0;
        },
        mode: FuzzMode.pureDart,
        fuzzerArgs: ['-runs=15', '-seed=42', corpusPath],
      );

      // First input in an empty corpus must be the 0-byte seed, without
      // injecting CRLF hex strings when no seed files exist.
      expect(seenRun1.first, isEmpty);
      expect(
        seenRun1.map(String.fromCharCodes),
        isNot(contains('7fffffffffffffff\r\n')),
      );

      // Newly discovered coverage-increasing inputs must be persisted to
      // corpusPath.
      final persistedFiles = Directory(corpusPath)
          .listSync()
          .whereType<File>()
          .toList();
      expect(persistedFiles, isNotEmpty);

      // Re-running with the same -seed against a fresh directory must explore
      // the exact same sequence of inputs.
      final corpusPath2 = '${d.sandbox}/pure_corpus_2';
      Directory(corpusPath2).createSync(recursive: true);
      final seenRun2 = <List<int>>[];
      FuzzRuntime.runDriver(
        (Uint8List data) {
          seenRun2.add(data.toList());
          $fuzzEdge(data.isEmpty ? 1 : (data.first + 2));
          return 0;
        },
        mode: FuzzMode.pureDart,
        fuzzerArgs: ['-runs=15', '-seed=42', corpusPath2],
      );
      expect(seenRun2, equals(seenRun1));
      expect(corpusDir.name, equals('pure_corpus'));
    });

    test('writes crash-<hash> reproducer file on unhandled exception with '
        '-artifact_prefix and -exact_artifact_path', () async {
      final scriptFile = File('${d.sandbox}/crash_harness.dart')
        ..writeAsStringSync('''
import 'dart:typed_data';
import 'package:fuzz/fuzz.dart';

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
      expect(prefixRes.exitCode, equals(77), reason: '${prefixRes.stderr}');
      expect(prefixRes.stderr as String, contains('Test unit written to'));
      final writtenFiles = artifactsDir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.contains('crash-'))
          .toList();
      expect(writtenFiles, hasLength(1));

      final exactPath = '${d.sandbox}/artifacts/exact_repro.bin';
      final exactRes = await Process.run(Platform.resolvedExecutable, [
        '--packages=$pkgConfig',
        scriptFile.path,
        '-runs=5',
        '-exact_artifact_path=$exactPath',
      ]);
      expect(exactRes.exitCode, equals(77), reason: '${exactRes.stderr}');
      expect(File(exactPath).existsSync(), isTrue);
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
      FuzzRuntime.covMap.fillRange(0, FuzzRuntime.numCounters, 0);
      FuzzRuntime.prevLoc = 0;

      $fuzzEdge(77);
      expect($fuzzEq(0xCAFEBABE, 0xCAFEBABE, 88), isTrue);
      expect($fuzzEq('magic', 'magic', 99), isTrue);
      expect($fuzzEq(const [0x46, 0x55], const [0x46, 0x5A], 100), isFalse);
      expect(
        FuzzRuntime.covMap.where((b) => b != 0).length,
        greaterThanOrEqualTo(4),
      );

      // Verify switching to pureDart and back to cgf preserves native siteHits
      // buffer identity.
      final nativeSiteHitsRef = FuzzRuntime.siteHits;
      FuzzRuntime.init(mode: FuzzMode.pureDart);
      expect(identical(FuzzRuntime.siteHits, nativeSiteHitsRef), isTrue);
      FuzzRuntime.init(mode: FuzzMode.cgf, libraryPath: libPath);
      expect(identical(FuzzRuntime.siteHits, nativeSiteHitsRef), isTrue);
    });
  });
}
