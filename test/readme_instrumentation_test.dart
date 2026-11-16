@TestOn('vm')
library;

import 'dart:io';

import 'package:checks/checks.dart';
import 'package:fuzz/src/instrument_ast.dart';
import 'package:test/test.dart';

void main() {
  test('README instrumentation sample matches AstInstrumentor output', () {
    final source = File('test/readme/check_header.dart').readAsStringSync();
    final golden = File('test/readme/check_header.instrumented.txt')
        .readAsStringSync();
    // The instrumentor emits a leading newline; the golden omits it so the
    // README code block does not start with a blank line.
    check(AstInstrumentor().instrumentSource(source).trimLeft()).equals(golden);
  });
}
