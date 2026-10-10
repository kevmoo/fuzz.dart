import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:checks/checks.dart';
import 'package:fuzz/src/crash_deduplicator.dart';
import 'package:path/path.dart' as p;
import 'package:stack_trace/stack_trace.dart';
import 'package:test/scaffolding.dart';
import 'package:test_descriptor/test_descriptor.dart' as d;

void main() {
  group('CrashDeduplicator', () {
    test('deduplicates crashes invariant to column offset and minimizes '
        'reproducer input length in place', () async {
      await d.dir('crashes').create();
      final prefix = '${p.join(d.sandbox, 'crashes')}/';
      final dedup = CrashDeduplicator(
        targetPackage: 'sample_pkg',
        artifactPrefix: prefix,
      );

      final traceCol10 = Trace.parse(
        '#0      parseItem (package:sample_pkg/src/parser.dart:42:10)\n'
        '#1      fuzzTarget (file:///tmp/target.dart:8:3)\n',
      );
      final traceCol99 = Trace.parse(
        '#0      parseItem (package:sample_pkg/src/parser.dart:42:99)\n'
        '#1      fuzzTarget (file:///tmp/target.dart:8:3)\n',
      );

      final longInput = Uint8List.fromList(
        utf8.encode('AAAA_LONG_CRASH_INPUT'),
      );
      final first = dedup.recordCrash(
        longInput,
        RangeError('index out of range'),
        traceCol10,
      );
      check(first)
        ..has((r) => r.isNew, 'isNew').isTrue()
        ..has((r) => r.isMinimized, 'isMinimized').isFalse()
        ..has((r) => r.record.index, 'record.index').equals(1)
        ..has((r) => r.record.hitCount, 'record.hitCount').equals(1);
      check(File(first.record.artifactPath).readAsBytesSync())
          .deepEquals(longInput);

      // Same line (42), different column (99), shorter input -> same bucket,
      // overwrites artifact file in place!
      final shortInput = Uint8List.fromList(utf8.encode('ABCD'));
      final second = dedup.recordCrash(
        shortInput,
        RangeError('index out of range'),
        traceCol99,
      );
      check(second)
        ..has((r) => r.isNew, 'isNew').isFalse()
        ..has((r) => r.isMinimized, 'isMinimized').isTrue()
        ..has(
          (r) => r.previousLength,
          'previousLength',
        ).equals(longInput.length)
        ..has((r) => r.record.index, 'record.index').equals(1)
        ..has((r) => r.record.hitCount, 'record.hitCount').equals(2)
        ..has(
          (r) => r.record.shortestInput,
          'record.shortestInput',
        ).deepEquals(shortInput);
      check(File(first.record.artifactPath).readAsBytesSync())
          .deepEquals(shortInput);

      // Longer input for the same signature does not overwrite shortestInput.
      final mediumInput = Uint8List.fromList(utf8.encode('MEDIUM_INPUT'));
      final third = dedup.recordCrash(
        mediumInput,
        RangeError('index out of range'),
        traceCol10,
      );
      check(third)
        ..has((r) => r.isNew, 'isNew').isFalse()
        ..has((r) => r.isMinimized, 'isMinimized').isFalse()
        ..has((r) => r.record.hitCount, 'record.hitCount').equals(3);
      check(File(first.record.artifactPath).readAsBytesSync())
          .deepEquals(shortInput);
      check(dedup)
        ..has((d) => d.records, 'records').length.equals(1)
        ..has((d) => d.totalHits, 'totalHits').equals(3);
    });

    test('disambiguates crashes in shared helper packages by targetPackage '
        'caller frame', () async {
      await d.dir('crashes').create();
      final prefix = '${p.join(d.sandbox, 'crashes')}/';
      final dedup = CrashDeduplicator(
        targetPackage: 'sass',
        artifactPrefix: prefix,
      );

      final traceA = Trace.parse(
        '#0      StringScanner.error (package:string_scanner/src/scanner.dart:99:5)\n'
        '#1      ScssParser.interpolation (package:sass/src/parse/scss.dart:120:7)\n',
      );
      final traceB = Trace.parse(
        '#0      StringScanner.error (package:string_scanner/src/scanner.dart:99:5)\n'
        '#1      StylesheetParser.mediaQuery (package:sass/src/parse/stylesheet.dart:250:9)\n',
      );

      final resA = dedup.recordCrash(
        Uint8List.fromList(utf8.encode('a')),
        StateError('scanner error'),
        traceA,
      );
      final resB = dedup.recordCrash(
        Uint8List.fromList(utf8.encode('b')),
        StateError('scanner error'),
        traceB,
      );

      check(resA)
        ..has((r) => r.isNew, 'isNew').isTrue()
        ..has((r) => r.record.primaryBlame, 'record.primaryBlame').equals(
          'ScssParser.interpolation (package:sass/src/parse/scss.dart:120)',
        );
      check(resB)
        ..has((r) => r.isNew, 'isNew').isTrue()
        ..has((r) => r.record.primaryBlame, 'record.primaryBlame').equals(
          'StylesheetParser.mediaQuery '
          '(package:sass/src/parse/stylesheet.dart:250)',
        );
      check(dedup.records).length.equals(2);

      final reportPath = p.join(d.sandbox, 'crashes_report.json');
      dedup.writeReportJson(reportPath);
      final jsonMap = jsonDecode(
        File(reportPath).readAsStringSync(),
      ) as Map<String, Object?>;
      check(jsonMap)
        ..['package'].equals('sass')
        ..['totalUniqueCrashes'].equals(2)
        ..['totalCrashHits'].equals(2);
    });

    test('formatDartInputLiteral formats printable UTF-8 and binary inputs '
        'cleanly', () {
      check(formatDartInputLiteral(Uint8List(0))).equals("''");
      check(formatDartInputLiteral(Uint8List.fromList(utf8.encode(r'[c\c'))))
          .equals(r"r'[c\c'");
      check(formatDartInputLiteral(Uint8List.fromList(utf8.encode("a'b\nc"))))
          .equals(r"'a\'b\nc'");
      check(formatDartInputLiteral(Uint8List.fromList([0xFF, 0x00, 0x41])))
          .equals('Uint8List.fromList([0xff, 0x00, 0x41])');
      // UTF-16 surrogate pair ('😀' = 2 code units) must not be split on
      // maxPreviewBytes truncation.
      check(
        formatDartInputLiteral(
          Uint8List.fromList(utf8.encode('ab😀cd')),
          maxPreviewBytes: 3,
        ),
      ).equals("r'ab...'");
      // C1 control characters (e.g. U+009B CSI) and U+2028 line separator fall
      // back to unambiguous byte literals.
      check(formatDartInputLiteral(Uint8List.fromList(utf8.encode('a\u009bb'))))
          .equals('Uint8List.fromList([0x61, 0xc2, 0x9b, 0x62])');
      check(formatDartInputLiteral(Uint8List.fromList(utf8.encode('a\u2028b'))))
          .equals('Uint8List.fromList([0x61, 0xe2, 0x80, 0xa8, 0x62])');
    });

    test('fromFuzzerArgs disables keepGoing on -exact_artifact_path=, '
        '-minimize_crash=1, and -keep_going=0', () {
      check(CrashDeduplicator.fromFuzzerArgs(const ['-runs=10']).keepGoing)
          .isTrue();
      check(
        CrashDeduplicator.fromFuzzerArgs(const [
          '-exact_artifact_path=/tmp/repro',
        ]).keepGoing,
      ).isFalse();
      check(
        CrashDeduplicator.fromFuzzerArgs(const ['-minimize_crash=1']).keepGoing,
      ).isFalse();
      check(CrashDeduplicator.fromFuzzerArgs(const ['-keep_going=0']).keepGoing)
          .isFalse();
    });
  });
}
