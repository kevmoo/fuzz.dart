import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:stack_trace/stack_trace.dart';

/// Computes the 64-bit FNV-1a digest of [data] as a 16-character hex string.
String fnv1a64Hex(Uint8List data) {
  var hash = 0xcbf29ce484222325;
  for (var i = 0; i < data.length; i++) {
    hash ^= data[i];
    hash = (hash * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF;
  }
  final hi = ((hash >>> 32) & 0xFFFFFFFF).toRadixString(16).padLeft(8, '0');
  final lo = (hash & 0xFFFFFFFF).toRadixString(16).padLeft(8, '0');
  return '$hi$lo';
}

/// Formats [data] as a copy-pasteable Dart literal (`r'...'` / `'...'` when
/// valid printable UTF-8, or `Uint8List.fromList([...])` for arbitrary bytes).
String formatDartInputLiteral(Uint8List data, {int? maxPreviewBytes}) {
  final text = _tryDecodePrintableUtf8(data);
  if (text != null) {
    final truncated = _truncateUtf16Safe(text, maxPreviewBytes);
    if (truncated.isEmpty) return "''";
    if (!_needsEscapingForRawSingleQuote(truncated)) return "r'$truncated'";
    final escaped = truncated
        .replaceAll(r'\', r'\\')
        .replaceAll("'", r"\'")
        .replaceAll(r'$', r'\$')
        .replaceAll('\n', r'\n')
        .replaceAll('\r', r'\r')
        .replaceAll('\t', r'\t');
    return "'$escaped'";
  }
  final limit = maxPreviewBytes != null && data.length > maxPreviewBytes
      ? maxPreviewBytes
      : data.length;
  final hexItems = [
    for (var i = 0; i < limit; i++)
      '0x${data[i].toRadixString(16).padLeft(2, '0')}',
    if (limit < data.length) '/* +${data.length - limit}B */',
  ].join(', ');
  return 'Uint8List.fromList([$hexItems])';
}

String _truncateUtf16Safe(String text, int? maxPreviewBytes) {
  if (maxPreviewBytes == null || text.length <= maxPreviewBytes) return text;
  var cut = maxPreviewBytes;
  if (cut > 0 && (text.codeUnitAt(cut - 1) & 0xFC00) == 0xD800) {
    cut--;
  }
  return '${text.substring(0, cut)}...';
}

String? _tryDecodePrintableUtf8(Uint8List data) {
  final String decoded;
  try {
    decoded = utf8.decode(data);
  } on FormatException {
    return null;
  }
  for (final rune in decoded.runes) {
    if (_isDisallowedTextRune(rune)) return null;
  }
  return decoded;
}

bool _isDisallowedTextRune(int rune) {
  if (rune < 0x20) {
    return rune != 0x09 && rune != 0x0A && rune != 0x0D;
  }
  return (rune >= 0x7F && rune <= 0x9F) ||
      rune == 0x2028 ||
      rune == 0x2029 ||
      rune == 0xFEFF;
}

bool _needsEscapingForRawSingleQuote(String s) {
  for (var i = 0; i < s.length; i++) {
    final c = s.codeUnitAt(i);
    if (c == 0x27 || c < 0x20) return true;
  }
  return false;
}

/// Deduplicated crash record captured during an in-process fuzzing session.
final class CrashRecord {
  final int index;
  final String signatureHash;
  final String errorType;
  String errorMessage;
  final String? originFrameLocation;
  final String? originFrameMember;
  final String? targetPackageFrameLocation;
  final String? targetPackageFrameMember;
  Uint8List shortestInput;
  final String artifactPath;
  String terseStackTrace;
  int hitCount = 1;

  CrashRecord({
    required this.index,
    required this.signatureHash,
    required this.errorType,
    required this.errorMessage,
    required this.originFrameLocation,
    required this.originFrameMember,
    required this.targetPackageFrameLocation,
    required this.targetPackageFrameMember,
    required this.shortestInput,
    required this.artifactPath,
    required this.terseStackTrace,
  });

  /// Human-readable primary blame frame (preferring the target package under
  /// test when present on the stack).
  String get primaryBlame {
    if (targetPackageFrameMember != null &&
        targetPackageFrameLocation != null) {
      return '$targetPackageFrameMember ($targetPackageFrameLocation)';
    }
    if (originFrameMember != null && originFrameLocation != null) {
      return '$originFrameMember ($originFrameLocation)';
    }
    return originFrameLocation ?? '<unknown>';
  }

  Map<String, Object?> toJson() => {
    'index': index,
    'signatureHash': signatureHash,
    'errorType': errorType,
    'errorMessage': errorMessage,
    'primaryBlame': primaryBlame,
    'originFrame': ?originFrameLocation,
    'originMember': ?originFrameMember,
    'targetPackageFrame': ?targetPackageFrameLocation,
    'targetPackageMember': ?targetPackageFrameMember,
    'hitCount': hitCount,
    'shortestInputLength': shortestInput.length,
    'shortestInputDartLiteral': formatDartInputLiteral(shortestInput),
    'shortestInputPreview': formatDartInputLiteral(
      shortestInput,
      maxPreviewBytes: 96,
    ),
    'artifactPath': artifactPath,
    'terseStackTrace': terseStackTrace,
  };
}

/// Deduplicates unhandled Dart exceptions by stack signature and minimizes
/// each unique crash's reproducer input length in-process.
final class CrashDeduplicator {
  final String? targetPackage;
  final String artifactPrefix;
  final String? exactArtifactPath;
  final bool keepGoing;
  final Map<String, CrashRecord> _records = <String, CrashRecord>{};
  int _totalHits = 0;

  CrashDeduplicator({
    this.targetPackage,
    this.artifactPrefix = './',
    this.exactArtifactPath,
    this.keepGoing = true,
  });

  factory CrashDeduplicator.fromFuzzerArgs(List<String> fuzzerArgs) {
    var prefix = './';
    String? exactPath;
    var keepGoing = Platform.environment['FUZZ_KEEP_GOING'] != '0';
    for (final arg in fuzzerArgs) {
      if (arg.startsWith('-exact_artifact_path=')) {
        final val = arg.substring('-exact_artifact_path='.length);
        if (val.isNotEmpty) {
          exactPath = val;
          keepGoing = false;
        }
      } else if (arg.startsWith('-artifact_prefix=')) {
        prefix = arg.substring('-artifact_prefix='.length);
      } else if (_isFailFastFlag(arg)) {
        keepGoing = false;
      } else if (arg == '-keep_going=1') {
        keepGoing = true;
      }
    }
    return CrashDeduplicator(
      targetPackage: Platform.environment['FUZZ_TARGET_PACKAGE'],
      artifactPrefix: prefix,
      exactArtifactPath: exactPath,
      keepGoing: keepGoing,
    );
  }

  static bool _isFailFastFlag(String arg) =>
      arg == '-keep_going=0' ||
      (arg.startsWith('-minimize_crash=') && arg != '-minimize_crash=0');

  List<CrashRecord> get records => _records.values.toList(growable: false);

  int get totalHits => _totalHits;

  bool get hasCrashes => _records.isNotEmpty;

  /// Writes [data] directly using [exactArtifactPath] or [artifactPrefix] and
  /// returns the written file path (used in fail-fast `--no-keep-going` mode).
  String writeRawArtifact(Uint8List data) {
    final path =
        exactArtifactPath ?? '${artifactPrefix}crash-${fnv1a64Hex(data)}';
    _writeBytes(path, data);
    return path;
  }

  /// Records an unhandled [error] and [st] for [data], writing or updating the
  /// corresponding crash artifact file only when the signature is new or [data]
  /// is strictly shorter than the previous shortest input for that signature.
  ({CrashRecord record, bool isNew, bool isMinimized, int previousLength})
  recordCrash(Uint8List data, Object error, StackTrace st) {
    _totalHits++;
    final trace = Trace.from(st);
    final (:originFrame, :targetFrame) = _selectBlameFrames(trace);
    final rawSig =
        '${error.runtimeType}|${_frameKey(originFrame)}|'
        '${_frameKey(targetFrame)}';
    final sigHash = fnv1a64Hex(Uint8List.fromList(utf8.encode(rawSig)));

    final existing = _records[sigHash];
    if (existing != null) {
      existing.hitCount++;
      final prevLen = existing.shortestInput.length;
      if (data.length < prevLen) {
        _writeBytes(existing.artifactPath, data);
        existing
          ..shortestInput = Uint8List.fromList(data)
          ..errorMessage = error.toString()
          ..terseStackTrace = _formatTerseTrace(trace);
        return (
          record: existing,
          isNew: false,
          isMinimized: true,
          previousLength: prevLen,
        );
      }
      return (
        record: existing,
        isNew: false,
        isMinimized: false,
        previousLength: prevLen,
      );
    }

    final artifactPath = exactArtifactPath ?? '${artifactPrefix}crash-$sigHash';
    _writeBytes(artifactPath, data);
    final record = CrashRecord(
      index: _records.length + 1,
      signatureHash: sigHash,
      errorType: error.runtimeType.toString(),
      errorMessage: error.toString(),
      originFrameLocation: _frameLineLocation(originFrame),
      originFrameMember: originFrame?.member,
      targetPackageFrameLocation: _frameLineLocation(targetFrame),
      targetPackageFrameMember: targetFrame?.member,
      shortestInput: Uint8List.fromList(data),
      artifactPath: artifactPath,
      terseStackTrace: _formatTerseTrace(trace),
    );
    _records[sigHash] = record;
    return (
      record: record,
      isNew: true,
      isMinimized: false,
      previousLength: data.length,
    );
  }

  ({Frame? originFrame, Frame? targetFrame}) _selectBlameFrames(Trace trace) {
    Frame? originFrame;
    Frame? targetFrame;
    final pkg = targetPackage;
    for (final frame in trace.frames) {
      if (frame.isCore ||
          frame.package == 'fuzz' ||
          frame.uri.path.endsWith('/fuzz_entrypoint.dart')) {
        continue;
      }
      originFrame ??= frame;
      if (pkg != null && pkg.isNotEmpty && frame.package == pkg) {
        targetFrame ??= frame;
      }
      if (pkg == null || targetFrame != null) break;
    }
    originFrame ??= trace.frames.isNotEmpty ? trace.frames.first : null;
    return (originFrame: originFrame, targetFrame: targetFrame);
  }

  // Column numbers are deliberately omitted from the signature key because AST
  // instrumentation (`$fuzzExpr(...)`) shifts horizontal column offsets while
  // preserving source line numbers.
  static String _frameKey(Frame? f) =>
      f == null ? '<none>' : '${f.uri}|${f.member ?? '?'}|${f.line ?? 0}';

  static String? _frameLineLocation(Frame? f) {
    if (f == null) return null;
    final base = f.library;
    return f.line != null ? '$base:${f.line}' : base;
  }

  static String _formatTerseTrace(Trace trace) => trace
      .foldFrames(
        (f) =>
            f.package == 'fuzz' || f.uri.path.endsWith('/fuzz_entrypoint.dart'),
        terse: true,
      )
      .toString()
      .trimRight();

  static void _writeBytes(String path, Uint8List data) {
    final file = File(path);
    file.parent.createSync(recursive: true);
    file.writeAsBytesSync(data);
  }

  /// Serializes the structured JSON crash summary as a formatted JSON string.
  String toReportJsonString() {
    final payload = <String, Object?>{
      'package': ?targetPackage,
      'totalUniqueCrashes': _records.length,
      'totalCrashHits': _totalHits,
      'crashes': [for (final r in _records.values) r.toJson()],
    };
    return const JsonEncoder.withIndent('  ').convert(payload);
  }

  /// Writes the structured JSON crash summary to [reportPath].
  void writeReportJson(String reportPath) {
    final file = File(reportPath);
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(toReportJsonString());
  }

  /// Formats a human-readable deduplicated crash summary table and reproducers.
  String formatSummaryReport() {
    if (_records.isEmpty) return '';
    return formatCrashSummaryFromJson(toReportJsonString());
  }
}

/// Formats a human-readable deduplicated crash summary from a serialized
/// `crashes_report.json` string.
String formatCrashSummaryFromJson(String reportJson) {
  final map = jsonDecode(reportJson) as Map<String, Object?>;
  final crashes =
      (map['crashes'] as List<Object?>?)?.cast<Map<String, Object?>>() ??
      const [];
  if (crashes.isEmpty) return '';
  final totalHits = map['totalCrashHits'] as int? ?? crashes.length;
  final sb = StringBuffer()
    ..writeln('\n========================================================')
    ..writeln(
      'DEDUPLICATED CRASH SUMMARY '
      '(${crashes.length} unique crash(es) across $totalHits hit(s))',
    )
    ..writeln('========================================================');
  for (final c in crashes) {
    _appendCrashSummaryEntry(sb, c);
  }
  return sb.toString();
}

void _appendCrashSummaryEntry(StringBuffer sb, Map<String, Object?> c) {
  final msg = (c['errorMessage'] as String? ?? '').split('\n').first;
  final stack = (c['terseStackTrace'] as String? ?? '')
      .split('\n')
      .take(6)
      .join('\n    ');
  final repro =
      c['shortestInputPreview'] ?? c['shortestInputDartLiteral'] ?? '';
  sb
    ..writeln(
      '[CRASH #${c['index']}] ${c['errorType']} @ ${c['primaryBlame']} '
      '(${c['hitCount']} hit(s), shortest: ${c['shortestInputLength']}B)',
    )
    ..writeln('  Message:    $msg')
    ..writeln('  Reproducer: $repro')
    ..writeln('  Artifact:   ${c['artifactPath']}')
    ..writeln('  Stack:\n    $stack')
    ..writeln('--------------------------------------------------------');
}
