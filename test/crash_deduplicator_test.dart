import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:fuzz/src/crash_deduplicator.dart';
import 'package:path/path.dart' as p;
import 'package:stack_trace/stack_trace.dart';
import 'package:test/test.dart';
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
      expect(first.isNew, isTrue);
      expect(first.isMinimized, isFalse);
      expect(first.record.index, equals(1));
      expect(first.record.hitCount, equals(1));
      expect(
        File(first.record.artifactPath).readAsBytesSync(),
        equals(longInput),
      );

      // Same line (42), different column (99), shorter input -> same bucket,
      // overwrites artifact file in place!
      final shortInput = Uint8List.fromList(utf8.encode('ABCD'));
      final second = dedup.recordCrash(
        shortInput,
        RangeError('index out of range'),
        traceCol99,
      );
      expect(second.isNew, isFalse);
      expect(second.isMinimized, isTrue);
      expect(second.previousLength, equals(longInput.length));
      expect(second.record.index, equals(1));
      expect(second.record.hitCount, equals(2));
      expect(second.record.shortestInput, equals(shortInput));
      expect(
        File(first.record.artifactPath).readAsBytesSync(),
        equals(shortInput),
      );

      // Longer input for the same signature does not overwrite shortestInput.
      final mediumInput = Uint8List.fromList(utf8.encode('MEDIUM_INPUT'));
      final third = dedup.recordCrash(
        mediumInput,
        RangeError('index out of range'),
        traceCol10,
      );
      expect(third.isNew, isFalse);
      expect(third.isMinimized, isFalse);
      expect(third.record.hitCount, equals(3));
      expect(
        File(first.record.artifactPath).readAsBytesSync(),
        equals(shortInput),
      );
      expect(dedup.records, hasLength(1));
      expect(dedup.totalHits, equals(3));
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

      expect(resA.isNew, isTrue);
      expect(resB.isNew, isTrue);
      expect(dedup.records, hasLength(2));
      expect(
        resA.record.primaryBlame,
        equals(
          'ScssParser.interpolation (package:sass/src/parse/scss.dart:120)',
        ),
      );
      expect(
        resB.record.primaryBlame,
        equals(
          'StylesheetParser.mediaQuery '
          '(package:sass/src/parse/stylesheet.dart:250)',
        ),
      );

      final reportPath = p.join(d.sandbox, 'crashes_report.json');
      dedup.writeReportJson(reportPath);
      final jsonMap = jsonDecode(
        File(reportPath).readAsStringSync(),
      ) as Map<String, Object?>;
      expect(jsonMap['package'], equals('sass'));
      expect(jsonMap['totalUniqueCrashes'], equals(2));
      expect(jsonMap['totalCrashHits'], equals(2));
    });

    test('formatDartInputLiteral formats printable UTF-8 and binary inputs '
        'cleanly', () {
      expect(formatDartInputLiteral(Uint8List(0)), equals("''"));
      expect(
        formatDartInputLiteral(Uint8List.fromList(utf8.encode(r'[c\c'))),
        equals(r"r'[c\c'"),
      );
      expect(
        formatDartInputLiteral(Uint8List.fromList(utf8.encode("a'b\nc"))),
        equals(r"'a\'b\nc'"),
      );
      expect(
        formatDartInputLiteral(Uint8List.fromList([0xFF, 0x00, 0x41])),
        equals('Uint8List.fromList([0xff, 0x00, 0x41])'),
      );
      // UTF-16 surrogate pair ('😀' = 2 code units) must not be split on
      // maxPreviewBytes truncation.
      expect(
        formatDartInputLiteral(
          Uint8List.fromList(utf8.encode('ab😀cd')),
          maxPreviewBytes: 3,
        ),
        equals("r'ab...'"),
      );
      // C1 control characters (e.g. U+009B CSI) and U+2028 line separator fall
      // back to unambiguous byte literals.
      expect(
        formatDartInputLiteral(Uint8List.fromList(utf8.encode('a\u009bb'))),
        equals('Uint8List.fromList([0x61, 0xc2, 0x9b, 0x62])'),
      );
      expect(
        formatDartInputLiteral(Uint8List.fromList(utf8.encode('a\u2028b'))),
        equals('Uint8List.fromList([0x61, 0xe2, 0x80, 0xa8, 0x62])'),
      );
    });

    test('fromFuzzerArgs disables keepGoing on -exact_artifact_path=, '
        '-minimize_crash=1, and -keep_going=0', () {
      expect(
        CrashDeduplicator.fromFuzzerArgs(const ['-runs=10']).keepGoing,
        isTrue,
      );
      expect(
        CrashDeduplicator.fromFuzzerArgs(const [
          '-exact_artifact_path=/tmp/repro',
        ]).keepGoing,
        isFalse,
      );
      expect(
        CrashDeduplicator.fromFuzzerArgs(const ['-minimize_crash=1']).keepGoing,
        isFalse,
      );
      expect(
        CrashDeduplicator.fromFuzzerArgs(const ['-keep_going=0']).keepGoing,
        isFalse,
      );
    });
  });
}
