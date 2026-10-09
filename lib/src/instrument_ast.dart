import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/token.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/source/line_info.dart';
import 'package:path/path.dart' as p;

import 'coverage_report.dart';

export 'coverage_report.dart' show FuzzSiteEntry;

enum _EditKind {
  /// Inserted at the end of an inner node (innermost first).
  suffix,

  /// Replaces an operator token.
  replace,

  /// Inserted at the start of an outer node (outermost first).
  prefix,
}

class _SourceEdit implements Comparable<_SourceEdit> {
  final int start;
  final int end;
  final _EditKind kind;
  final int depth;
  final int seq;
  final String replacement;

  _SourceEdit({
    required this.start,
    required this.end,
    required this.kind,
    required this.depth,
    required this.seq,
    required this.replacement,
  });

  @override
  int compareTo(_SourceEdit other) {
    final cmpStart = start.compareTo(other.start);
    if (cmpStart != 0) return cmpStart;
    final cmpEnd = end.compareTo(other.end);
    if (cmpEnd != 0) return cmpEnd;
    final cmpKind = kind.index.compareTo(other.kind.index);
    if (cmpKind != 0) return cmpKind;
    // Prefix edits order outermost first; others order innermost first.
    final cmpDepth = kind == _EditKind.prefix
        ? depth.compareTo(other.depth)
        : other.depth.compareTo(depth);
    if (cmpDepth != 0) return cmpDepth;
    return kind == _EditKind.prefix
        ? seq.compareTo(other.seq)
        : other.seq.compareTo(seq);
  }
}

/// Rewrites Dart source files with SanitizerCoverage-style edge and comparison
/// hooks (`$fuzzEdge`, `$fuzzEq`, `$fuzzLt`, `$fuzzSwitch`, etc.).
class AstInstrumentor {
  int _nextId = 1;
  int edgesInserted = 0;
  int comparesInserted = 0;
  int switchesInserted = 0;

  /// Every AST site instrumented across one or more [instrumentSource] calls.
  final List<FuzzSiteEntry> sites = [];

  /// String and character literals harvested from instrumented ASTs for
  /// `libFuzzer` dictionary pre-seeding (`-dict=`).
  final Set<String> dictionaryTokens = {};

  int _allocSite({
    required int offset,
    required String kind,
    required LineInfo lineInfo,
    required String filePath,
  }) {
    final id = (_nextId * 40503) & 0xFFFF;
    _nextId++;
    final nonZeroId = id == 0 ? 1 : id;
    final loc = lineInfo.getLocation(offset);
    sites.add((
      id: nonZeroId,
      file: filePath,
      line: loc.lineNumber,
      column: loc.columnNumber,
      kind: kind,
    ));
    return nonZeroId;
  }

  /// Instruments [source] with `$fuzzEdge`, `$fuzzEq`/`$fuzzLt`/etc., and
  /// `$fuzzSwitch` calls into [runtimeImport].
  ///
  /// Automatically omits the `import` directive if [source] is a `part of`
  /// compilation unit (which inherits imports from its owning library).
  String instrumentSource(
    String source, {
    String runtimeImport = 'package:fuzz/src/fuzz_runtime.dart',
    bool addImport = true,
    String filePath = '<memory>',
  }) {
    final parseResult = parseString(content: source, throwIfDiagnostics: false);
    final unit = parseResult.unit;
    final visitor = _InstrumentVisitor(
      this,
      filePath: filePath,
      lineInfo: parseResult.lineInfo,
    );
    unit.accept(visitor);

    final edits = visitor.edits..sort();

    final sb = StringBuffer();
    var cursor = 0;
    for (final edit in edits) {
      if (edit.start < cursor) continue;
      sb
        ..write(source.substring(cursor, edit.start))
        ..write(edit.replacement);
      cursor = edit.end;
    }
    sb.write(source.substring(cursor));

    final instrumentedBody = sb.toString();
    final isPartOf = unit.directives.any((d) => d is PartOfDirective);
    final hasPartDirective = unit.directives.any((d) => d is PartDirective);
    if (edits.isEmpty && !hasPartDirective) return source;
    if (!addImport || isPartOf) {
      if (edits.isEmpty) return instrumentedBody;
      return '$instrumentedBody\n'
          '// ignore_for_file: type=lint, unawaited_return_in_try_block, '
          'duplicate_ignore\n';
    }

    final insertPos = _findImportInsertOffset(unit);
    final ignored = edits.isEmpty
        ? 'type=lint, unused_import, duplicate_ignore'
        : 'type=lint, unawaited_return_in_try_block, duplicate_ignore';
    return '${instrumentedBody.substring(0, insertPos)}\n'
        "import '$runtimeImport'; // ignore_for_file: $ignored\n"
        '${instrumentedBody.substring(insertPos)}';
  }

  static int _findImportInsertOffset(CompilationUnit unit) {
    for (final directive in unit.directives) {
      if (directive is LibraryDirective) return directive.end;
    }
    if (unit.directives.isNotEmpty) {
      return unit.directives.first.offset;
    }
    if (unit.declarations.isNotEmpty) {
      return unit.declarations.first.offset;
    }
    return 0;
  }
}

class _InstrumentVisitor extends RecursiveAstVisitor<void> {
  final AstInstrumentor owner;
  final String filePath;
  final LineInfo lineInfo;
  final List<_SourceEdit> edits = [];
  int _nextSeq = 0;

  _InstrumentVisitor(
    this.owner, {
    required this.filePath,
    required this.lineInfo,
  });

  int _depth(AstNode node) {
    var d = 0;
    for (var cur = node.parent; cur != null; cur = cur.parent) {
      d++;
    }
    return d;
  }

  bool _inConstOrNonInstrumentableContext(AstNode node) {
    for (AstNode? cur = node; cur != null; cur = cur.parent) {
      if (_isNonInstrumentableAncestor(cur, node)) return true;
    }
    return false;
  }

  static bool _isNonInstrumentableAncestor(AstNode current, AstNode leaf) =>
      switch (current) {
        VariableDeclarationList(:final isConst) => isConst,
        InstanceCreationExpression(:final isConst) => isConst,
        DotShorthandConstructorInvocation(:final isConst) => isConst,
        TypedLiteral(:final isConst) => isConst,
        RecordLiteral(:final isConst) => isConst,
        ConstructorDeclaration(:final constKeyword) => constKeyword != null,
        Annotation() ||
        AssertStatement() ||
        ConstantPattern() ||
        RelationalPattern() ||
        ConstructorInitializer() ||
        FormalParameter() ||
        EnumConstantArguments() => true,
        SwitchCase(:final expression) => _isInside(leaf, expression),
        SwitchPatternCase(:final guardedPattern) => _isInside(
          leaf,
          guardedPattern.pattern,
        ),
        SwitchExpressionCase(:final guardedPattern) => _isInside(
          leaf,
          guardedPattern.pattern,
        ),
        _ => false,
      };

  static bool _isInside(AstNode leaf, AstNode target) =>
      leaf.thisOrAncestorMatching((n) => identical(n, target)) != null;

  void _wrapStatementWithEdge(Statement stmt) {
    final id = owner._allocSite(
      offset: stmt.offset,
      kind: 'branch',
      lineInfo: lineInfo,
      filePath: filePath,
    );
    owner.edgesInserted++;
    final d = _depth(stmt);
    final seq = _nextSeq++;
    edits
      ..add(
        _SourceEdit(
          start: stmt.offset,
          end: stmt.offset,
          kind: _EditKind.prefix,
          depth: d,
          seq: seq,
          replacement: '{ \$fuzzEdge($id); ',
        ),
      )
      ..add(
        _SourceEdit(
          start: stmt.end,
          end: stmt.end,
          kind: _EditKind.suffix,
          depth: d,
          seq: seq,
          replacement: ' }',
        ),
      );
  }

  void _wrapExprWithEdge(
    Expression expr, {
    String kind = 'branch',
    bool preserveConditionFlow = false,
  }) {
    final unp = expr.unParenthesized;
    if (unp is RethrowExpression) return;
    if (unp is! ThrowExpression && _alwaysThrows(unp)) return;
    if (unp is! ThrowExpression && _isInsideAssignmentRhs(expr)) return;
    if (unp is! ThrowExpression && _isInsideNumericDispatchRhs(expr)) return;
    if (unp is! ThrowExpression && _isInVoidPermittingContext(expr)) return;
    if (preserveConditionFlow && unp is! ThrowExpression) {
      final finder = _ConditionFlowFinder();
      unp.accept(finder);
      if (finder.found) return;
    }
    final target = unp is ThrowExpression ? unp.expression : expr;
    final id = owner._allocSite(
      offset: expr.offset,
      kind: kind,
      lineInfo: lineInfo,
      filePath: filePath,
    );
    owner.edgesInserted++;
    final d = _depth(target);
    final seq = _nextSeq++;
    edits
      ..add(
        _SourceEdit(
          start: target.offset,
          end: target.offset,
          kind: _EditKind.prefix,
          depth: d,
          seq: seq,
          replacement: '\$fuzzExpr($id, ',
        ),
      )
      ..add(
        _SourceEdit(
          start: target.end,
          end: target.end,
          kind: _EditKind.suffix,
          depth: d,
          seq: seq,
          replacement: ')',
        ),
      );
  }

  static bool _alwaysThrows(Expression expr) => switch (expr.unParenthesized) {
    ThrowExpression() || RethrowExpression() => true,
    ConditionalExpression(:final thenExpression, :final elseExpression) =>
      _alwaysThrows(thenExpression) && _alwaysThrows(elseExpression),
    SwitchExpression(:final cases) =>
      cases.isNotEmpty && cases.every((c) => _alwaysThrows(c.expression)),
    _ => false,
  };

  static bool _isInsideAssignmentRhs(AstNode node) {
    for (
      var cur = node.parent;
      cur != null &&
          cur is! Statement &&
          cur is! FunctionDeclaration &&
          cur is! MethodDeclaration;
      cur = cur.parent
    ) {
      if (cur is AssignmentExpression ||
          cur is VariableDeclaration ||
          cur is PatternAssignment) {
        return true;
      }
    }
    return false;
  }

  /// Returns `true` when [expr] is positioned inside the right-hand operand of
  /// `+`, `-`, `*`, or `%` (or an argument to `remainder` / `clamp`), where
  /// `int` operators impose downward context type `num` while still refining
  /// their static return type to `int` only if the operand's static type stays
  /// `int`. Wrapping [expr] in generic `$fuzzExpr<T>` under context `num`
  /// would solve `T = num` and break outer `int` return/argument types.
  static bool _isInsideNumericDispatchRhs(Expression expr) {
    AstNode? cur = expr;
    while (cur != null) {
      final parent = cur.parent;
      if (parent is ParenthesizedExpression ||
          parent is SwitchExpressionCase ||
          (parent is ConditionalExpression && cur != parent.condition) ||
          (parent is SwitchExpression && cur != parent.expression) ||
          (parent is CascadeExpression && cur == parent.target) ||
          (parent is BinaryExpression &&
              parent.operator.type == TokenType.QUESTION_QUESTION)) {
        cur = parent;
        continue;
      }
      if (parent is BinaryExpression && cur == parent.rightOperand) {
        final op = parent.operator.type;
        return op == TokenType.PLUS ||
            op == TokenType.MINUS ||
            op == TokenType.STAR ||
            op == TokenType.PERCENT;
      }
      if (parent is ArgumentList) {
        if (parent.parent case MethodInvocation(:final methodName)) {
          final name = methodName.name;
          return name == 'remainder' || name == 'clamp';
        }
      }
      return false;
    }
    return false;
  }

  static bool _isInVoidPermittingContext(Expression expr) {
    final unp = expr.unParenthesized;
    if (unp is Literal ||
        unp is BinaryExpression ||
        unp is PrefixExpression ||
        unp is IsExpression ||
        unp is AsExpression ||
        unp is SwitchExpression) {
      return false;
    }
    AstNode? cur = expr;
    while (cur != null) {
      final parent = cur.parent;
      if (parent is ParenthesizedExpression ||
          parent is ConditionalExpression) {
        cur = parent;
        continue;
      }
      if (parent is ExpressionStatement || parent is ForParts) {
        return true;
      }
      if (parent is ExpressionFunctionBody) {
        return !_hasExplicitNonVoidReturnType(parent);
      }
      return false;
    }
    return false;
  }

  static bool _hasExplicitNonVoidReturnType(ExpressionFunctionBody body) {
    if (body.isAsynchronous || body.isGenerator) return false;
    final parent = body.parent;
    final returnType = switch (parent) {
      MethodDeclaration(:final returnType) => returnType,
      FunctionExpression(parent: FunctionDeclaration(:final returnType)) =>
        returnType,
      _ => null,
    };
    if (returnType is NamedType) {
      final name = returnType.name.lexeme;
      return name != 'void' && name != 'dynamic' && name != 'FutureOr';
    }
    return returnType != null;
  }

  void _wrapConditionWithBool(Expression cond) {
    final unp = cond.unParenthesized;
    if (unp is BooleanLiteral) return;
    final finder = _FlowSensitiveFinder();
    unp.accept(finder);
    if (finder.found) return;
    if (unp is BinaryExpression) {
      final op = unp.operator.type;
      if (op == TokenType.AMPERSAND_AMPERSAND || op == TokenType.BAR_BAR) {
        _wrapConditionWithBool(unp.leftOperand);
        _wrapConditionWithBool(unp.rightOperand);
      }
      return;
    }
    final id = owner._allocSite(
      offset: cond.offset,
      kind: 'cmp',
      lineInfo: lineInfo,
      filePath: filePath,
    );
    owner.comparesInserted++;
    final d = _depth(cond);
    final seq = _nextSeq++;
    edits
      ..add(
        _SourceEdit(
          start: cond.offset,
          end: cond.offset,
          kind: _EditKind.prefix,
          depth: d,
          seq: seq,
          replacement: r'$fuzzBool(',
        ),
      )
      ..add(
        _SourceEdit(
          start: cond.end,
          end: cond.end,
          kind: _EditKind.suffix,
          depth: d,
          seq: seq,
          replacement: ', $id)',
        ),
      );
  }

  @override
  void visitBlock(Block node) {
    if (!_inConstOrNonInstrumentableContext(node)) {
      final siteOffset = node.statements.isNotEmpty
          ? node.statements.first.offset
          : node.leftBracket.offset;
      final id = owner._allocSite(
        offset: siteOffset,
        kind: 'block',
        lineInfo: lineInfo,
        filePath: filePath,
      );
      owner.edgesInserted++;
      edits.add(
        _SourceEdit(
          start: node.leftBracket.end,
          end: node.leftBracket.end,
          kind: _EditKind.prefix,
          depth: _depth(node),
          seq: _nextSeq++,
          replacement: ' \$fuzzEdge($id);',
        ),
      );
    }
    super.visitBlock(node);
  }

  @override
  void visitIfStatement(IfStatement node) {
    if (!_inConstOrNonInstrumentableContext(node)) {
      if (node.caseClause == null) {
        _wrapConditionWithBool(node.expression);
      }
      final thenStmt = node.thenStatement;
      if (thenStmt is! Block) {
        _wrapStatementWithEdge(thenStmt);
      }
      final elseStmt = node.elseStatement;
      if (elseStmt != null && elseStmt is! Block && elseStmt is! IfStatement) {
        _wrapStatementWithEdge(elseStmt);
      }
    }
    super.visitIfStatement(node);
  }

  @override
  void visitForStatement(ForStatement node) {
    if (!_inConstOrNonInstrumentableContext(node)) {
      if (node.forLoopParts case ForParts(:final condition?)) {
        _wrapConditionWithBool(condition);
      }
      if (node.body is! Block) {
        _wrapStatementWithEdge(node.body);
      }
    }
    super.visitForStatement(node);
  }

  @override
  void visitWhileStatement(WhileStatement node) {
    if (!_inConstOrNonInstrumentableContext(node)) {
      _wrapConditionWithBool(node.condition);
      if (node.body is! Block) {
        _wrapStatementWithEdge(node.body);
      }
    }
    super.visitWhileStatement(node);
  }

  @override
  void visitDoStatement(DoStatement node) {
    if (!_inConstOrNonInstrumentableContext(node)) {
      if (node.body is! Block) {
        _wrapStatementWithEdge(node.body);
      }
      _wrapConditionWithBool(node.condition);
    }
    super.visitDoStatement(node);
  }

  @override
  void visitConditionalExpression(ConditionalExpression node) {
    if (!_inConstOrNonInstrumentableContext(node)) {
      _wrapConditionWithBool(node.condition);
      _wrapExprWithEdge(node.thenExpression, preserveConditionFlow: true);
      _wrapExprWithEdge(node.elseExpression, preserveConditionFlow: true);
    }
    super.visitConditionalExpression(node);
  }

  @override
  void visitExpressionFunctionBody(ExpressionFunctionBody node) {
    if (_hasExplicitNonVoidReturnType(node) &&
        !_inConstOrNonInstrumentableContext(node)) {
      _wrapExprWithEdge(node.expression, kind: 'block');
    }
    super.visitExpressionFunctionBody(node);
  }

  @override
  void visitSwitchExpression(SwitchExpression node) {
    if (!_inConstOrNonInstrumentableContext(node)) {
      for (final member in node.cases) {
        _wrapExprWithEdge(member.expression, kind: 'switch_case');
      }
    }
    super.visitSwitchExpression(node);
  }

  static bool _isDotShorthand(Expression expr) {
    final unp = expr.unParenthesized;
    return unp is DotShorthandInvocation ||
        unp is DotShorthandPropertyAccess ||
        unp is DotShorthandConstructorInvocation;
  }

  static String? _switchMemberCaseSource(SwitchMember member) =>
      switch (member) {
        SwitchCase(:final expression)
            when expression.unParenthesized is! NullLiteral &&
                !_isDotShorthand(expression) =>
          expression.toSource(),
        SwitchPatternCase(
          guardedPattern: GuardedPattern(
            pattern: ConstantPattern(:final expression),
            whenClause: null,
          ),
        )
            when expression.unParenthesized is! NullLiteral &&
                !_isDotShorthand(expression) =>
          expression.toSource(),
        _ => null,
      };

  @override
  void visitSwitchStatement(SwitchStatement node) {
    if (!_inConstOrNonInstrumentableContext(node)) {
      _instrumentSwitchStatement(node);
    }
    super.visitSwitchStatement(node);
  }

  void _instrumentSwitchStatement(SwitchStatement node) {
    var canWrapScrutinee = !_isDotShorthand(node.expression);
    final caseExprs = <String>[];
    for (final member in node.members) {
      if (member is! SwitchDefault) {
        final caseSource = _switchMemberCaseSource(member);
        if (caseSource != null) {
          caseExprs.add(caseSource);
        } else {
          canWrapScrutinee = false;
        }
      }
      if (member.statements.isNotEmpty) {
        _addSwitchMemberEdge(member);
      }
    }
    if (canWrapScrutinee && caseExprs.isNotEmpty) {
      _wrapSwitchScrutinee(node, caseExprs);
    }
  }

  void _addSwitchMemberEdge(SwitchMember member) {
    final edgeId = owner._allocSite(
      offset: member.offset,
      kind: 'switch_case',
      lineInfo: lineInfo,
      filePath: filePath,
    );
    owner.edgesInserted++;
    edits.add(
      _SourceEdit(
        start: member.colon.end,
        end: member.colon.end,
        kind: _EditKind.prefix,
        depth: _depth(member),
        seq: _nextSeq++,
        replacement: ' \$fuzzEdge($edgeId);',
      ),
    );
  }

  void _wrapSwitchScrutinee(SwitchStatement node, List<String> caseExprs) {
    final switchId = owner._allocSite(
      offset: node.offset,
      kind: 'switch',
      lineInfo: lineInfo,
      filePath: filePath,
    );
    owner.switchesInserted++;
    final expr = node.expression;
    final d = _depth(expr);
    final seq = _nextSeq++;
    edits
      ..add(
        _SourceEdit(
          start: expr.offset,
          end: expr.offset,
          kind: _EditKind.prefix,
          depth: d,
          seq: seq,
          replacement: r'$fuzzSwitch(',
        ),
      )
      ..add(
        _SourceEdit(
          start: expr.end,
          end: expr.end,
          kind: _EditKind.suffix,
          depth: d,
          seq: seq,
          replacement: ', <Object?>[${caseExprs.join(', ')}], $switchId)',
        ),
      );
  }

  static String? _operatorHelper(TokenType op) => switch (op) {
    TokenType.EQ_EQ => r'$fuzzEq',
    TokenType.BANG_EQ => r'$fuzzNe',
    TokenType.LT => r'$fuzzLt',
    TokenType.LT_EQ => r'$fuzzLe',
    TokenType.GT => r'$fuzzGt',
    TokenType.GT_EQ => r'$fuzzGe',
    TokenType.CARET => r'$fuzzXor',
    _ => null,
  };

  static bool _hasNullOrBoolLiteral(BinaryExpression node) {
    final left = node.leftOperand.unParenthesized;
    final right = node.rightOperand.unParenthesized;
    return left is SuperExpression ||
        left is NullLiteral ||
        right is NullLiteral ||
        left is BooleanLiteral ||
        right is BooleanLiteral ||
        _isDotShorthand(left) ||
        _isDotShorthand(right);
  }

  @override
  void visitBinaryExpression(BinaryExpression node) {
    final helper =
        (_inConstOrNonInstrumentableContext(node) ||
            _hasNullOrBoolLiteral(node))
        ? null
        : _operatorHelper(node.operator.type);
    if (helper != null) {
      final id = owner._allocSite(
        offset: node.operator.offset,
        kind: 'cmp',
        lineInfo: lineInfo,
        filePath: filePath,
      );
      owner.comparesInserted++;
      final d = _depth(node);
      final seq = _nextSeq++;
      edits
        ..add(
          _SourceEdit(
            start: node.offset,
            end: node.offset,
            kind: _EditKind.prefix,
            depth: d,
            seq: seq,
            replacement: '$helper(',
          ),
        )
        ..add(
          _SourceEdit(
            start: node.leftOperand.end,
            end: node.rightOperand.offset,
            kind: _EditKind.replace,
            depth: d,
            seq: seq,
            replacement: ', ',
          ),
        )
        ..add(
          _SourceEdit(
            start: node.end,
            end: node.end,
            kind: _EditKind.suffix,
            depth: d,
            seq: seq,
            replacement: ', $id)',
          ),
        );
    }
    super.visitBinaryExpression(node);
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    final val = node.value;
    if (_isInsideRegExpCall(node) || _regexMetaFragments.hasMatch(val)) {
      _harvestRegExpTokens(val);
    } else if (_isCandidateDictString(val) &&
        !_isDirectiveOrErrorLiteral(node) &&
        !_isInsideLargeLiteralCollection(node)) {
      owner.dictionaryTokens.add(val);
    }
    super.visitSimpleStringLiteral(node);
  }

  @override
  void visitIntegerLiteral(IntegerLiteral node) {
    final val = node.value;
    if (val != null &&
        ((val >= 0x20 && val <= 0x7E) ||
            val == 0x09 ||
            val == 0x0A ||
            val == 0x0D) &&
        _isComparisonOrSwitchLiteral(node)) {
      owner.dictionaryTokens.add(String.fromCharCode(val));
    }
    super.visitIntegerLiteral(node);
  }

  void _harvestRegExpTokens(String pattern) {
    if (pattern.contains(r'\d')) owner.dictionaryTokens.add('0');
    if (pattern.contains(r'\r\n')) owner.dictionaryTokens.add('\r\n');
    for (final rawBranch in pattern.split('|')) {
      if (_plainRegexBranch.hasMatch(rawBranch) &&
          _isCandidateDictString(rawBranch)) {
        owner.dictionaryTokens.add(rawBranch);
      }
    }
  }

  static final RegExp _plainRegexBranch = RegExp(r'^[A-Za-z0-9_ ,:;/-]+$');
  static final RegExp _regexMetaFragments = RegExp(
    r'\(\?:|\[[a-zA-Z0-9^]|\\[dsSwWbB]',
  );

  static bool _isCandidateDictString(String val) =>
      val.isNotEmpty && val.length <= 24 && ' '.allMatches(val).length <= 1;

  static bool _isComparisonOrSwitchLiteral(AstNode node) =>
      switch (node.parent) {
        BinaryExpression(:final operator) =>
          _operatorHelper(operator.type) != null,
        SwitchCase() || ConstantPattern() || RelationalPattern() => true,
        _ => false,
      };

  static bool _isInsideRegExpCall(AstNode node) {
    final parent = node.parent;
    if (parent is! ArgumentList) return false;
    return switch (parent.parent) {
      MethodInvocation(:final methodName) => methodName.name == 'RegExp',
      InstanceCreationExpression(:final constructorName) =>
        constructorName.type.name.lexeme == 'RegExp',
      _ => false,
    };
  }

  static bool _isInsideLargeLiteralCollection(AstNode node) {
    for (var cur = node.parent; cur != null; cur = cur.parent) {
      if (cur is SetOrMapLiteral && cur.elements.length > 32) return true;
      if (cur is ListLiteral && cur.elements.length > 32) return true;
    }
    return false;
  }

  static bool _isDirectiveOrErrorLiteral(AstNode node) {
    for (var cur = node.parent; cur != null; cur = cur.parent) {
      if (_isExcludedAstContainer(cur)) return true;
    }
    return false;
  }

  static bool _isExcludedAstContainer(AstNode cur) => switch (cur) {
    Directive() ||
    Annotation() ||
    AssertStatement() ||
    ThrowExpression() ||
    EnumConstantArguments() => true,
    InstanceCreationExpression(:final constructorName) =>
      constructorName.type.name.lexeme == 'StateError' ||
          constructorName.type.name.lexeme.endsWith('Exception') ||
          constructorName.type.name.lexeme.endsWith('Error'),
    MethodInvocation(:final methodName) =>
      methodName.name.toLowerCase().contains('error') ||
          methodName.name.toLowerCase().contains('exception') ||
          methodName.name.toLowerCase().contains('fail') ||
          methodName.name.toLowerCase().contains('warn'),
    _ => _isErrorNamedArgument(cur),
  };

  static bool _isErrorNamedArgument(AstNode cur) {
    if (cur.parent is! ArgumentList) return false;
    final tok = cur.beginToken;
    return tok.next?.lexeme == ':' &&
        (tok.lexeme == 'name' || tok.lexeme == 'message');
  }
}

/// Formats [tokens] as an AFL / `libFuzzer` dictionary (`"escaped_token"` per
/// line).
String formatFuzzDictionary(Iterable<String> tokens) {
  final sorted = tokens.where((t) => t.isNotEmpty).toSet().toList()..sort();
  final sb = StringBuffer();
  for (final token in sorted) {
    sb
      ..write('"')
      ..write(_escapeDictionaryToken(utf8.encode(token)))
      ..writeln('"');
  }
  return sb.toString();
}

String _escapeDictionaryToken(List<int> bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    if (b >= 0x20 && b <= 0x7E && b != 0x22 && b != 0x5C) {
      sb.writeCharCode(b);
    } else {
      sb
        ..write(r'\x')
        ..write(b.toRadixString(16).padLeft(2, '0'));
    }
  }
  return sb.toString();
}

class _FlowSensitiveFinder extends GeneralizingAstVisitor<void> {
  bool found = false;

  @override
  void visitNode(AstNode node) {
    if (found) return;
    if (node is IsExpression ||
        node is AsExpression ||
        node is NullLiteral ||
        node is BooleanLiteral ||
        node is AssignmentExpression ||
        node is PatternAssignment ||
        node is ThrowExpression ||
        node is RethrowExpression) {
      found = true;
      return;
    }
    super.visitNode(node);
  }
}

class _ConditionFlowFinder extends GeneralizingAstVisitor<void> {
  bool found = false;

  @override
  void visitNode(AstNode node) {
    if (found) return;
    if (node is IsExpression || node is NullLiteral || node is BooleanLiteral) {
      found = true;
      return;
    }
    super.visitNode(node);
  }
}

/// Summary of a `.dart_tool/fuzz/` package overlay instrumentation pass.
typedef OverlayResult = ({
  String packageName,
  String overlayPackageConfigPath,
  String edgeManifestPath,
  String dictionaryPath,
  String instrumentedLibDir,
  int filesInstrumented,
  int edgesInserted,
  int comparesInserted,
  int switchesInserted,
  int dictionaryTokensExtracted,
  bool cached,
});

typedef _OverlayCacheContext = ({
  String fuzzDir,
  String packageName,
  String runtimeImport,
  List<String> normalizedDeps,
  Map<String, String> inputFingerprints,
});

/// Builds a non-destructive AST-instrumented copy of a target package's `lib/`
/// directory (plus any requested dependency packages) inside
/// `<workDir>/instrumented/` and writes an overlay
/// `<workDir>/package_config.json`.
class PackageOverlayInstrumentor {
  static const int _overlayCacheVersion = 1;

  /// Instruments `<packageRoot>/lib` (and any [additionalPackages] from
  /// `package_config.json`) into [workDir] (defaulting to
  /// `<packageRoot>/.dart_tool/fuzz/`) without modifying any tracked files in
  /// [packageRoot].
  ///
  /// When [force] is `false` (the default), reuses an existing up-to-date
  /// overlay in `<workDir>/` without re-parsing ASTs if no source, config, or
  /// `package:fuzz` files have changed.
  static Future<OverlayResult> instrumentPackage({
    required String packageRoot,
    String runtimeImport = 'package:fuzz/src/fuzz_runtime.dart',
    String? workDir,
    List<String> additionalPackages = const [],
    bool force = false,
  }) async {
    final rootDir = p.normalize(p.absolute(packageRoot));
    final pubspecFile = File(p.join(rootDir, 'pubspec.yaml'));
    if (!pubspecFile.existsSync()) {
      throw ArgumentError('No pubspec.yaml found in $rootDir');
    }

    final packageName = _extractPackageName(pubspecFile.readAsStringSync());
    final sourceLibDir = Directory(p.join(rootDir, 'lib'));
    if (!sourceLibDir.existsSync()) {
      throw ArgumentError('No lib/ directory found in $rootDir');
    }

    final fuzzDir = workDir != null && workDir.isNotEmpty
        ? p.normalize(p.absolute(workDir))
        : p.join(rootDir, '.dart_tool', 'fuzz');
    final instrumentedRoot = p.join(fuzzDir, 'instrumented');
    final instrumentedLibDir = p.join(instrumentedRoot, 'lib');
    final pkgConfigFile = _findPackageConfigFile(rootDir);
    final rawJson =
        jsonDecode(pkgConfigFile.readAsStringSync()) as Map<String, Object?>;
    final configDir = p.dirname(pkgConfigFile.path);
    final packages = (rawJson['packages'] as List<Object?>)
        .cast<Map<String, Object?>>();

    final normalizedDeps =
        additionalPackages
            .where((d) => d.isNotEmpty && d != packageName)
            .toSet()
            .toList()
          ..sort();
    final depLibDirs = <String, Directory>{
      for (final depName in normalizedDeps)
        depName: _resolveDependencyLibDir(packages, depName, configDir),
    };
    final inputFingerprints = await _computeOverlayInputFingerprints(
      rootDir,
      fuzzDir,
      pkgConfigFile,
      depLibDirs,
    );
    final cacheCtx = (
      fuzzDir: fuzzDir,
      packageName: packageName,
      runtimeImport: runtimeImport,
      normalizedDeps: normalizedDeps,
      inputFingerprints: inputFingerprints,
    );

    if (!force) {
      final cached = _tryLoadCachedOverlay(cacheCtx);
      if (cached != null) return cached;
    }

    final cacheFile = File(p.join(fuzzDir, 'overlay_cache.json'));
    if (cacheFile.existsSync()) {
      cacheFile.deleteSync();
    }
    final rootOutDir = Directory(instrumentedRoot);
    if (rootOutDir.existsSync()) {
      rootOutDir.deleteSync(recursive: true);
    }
    Directory(instrumentedLibDir).createSync(recursive: true);

    final instrumentor = AstInstrumentor();
    var filesInstrumented = _instrumentDirectoryTree(
      sourceLibDir: sourceLibDir,
      instrumentedLibDir: instrumentedLibDir,
      instrumentor: instrumentor,
      runtimeImport: runtimeImport,
    );

    for (final entry in depLibDirs.entries) {
      final depName = entry.key;
      final depOutLibDir = p.join(instrumentedRoot, depName, 'lib');
      Directory(depOutLibDir).createSync(recursive: true);
      filesInstrumented += _instrumentDirectoryTree(
        sourceLibDir: entry.value,
        instrumentedLibDir: depOutLibDir,
        instrumentor: instrumentor,
        runtimeImport: runtimeImport,
        filePrefix: 'package:$depName/lib',
      );
    }

    final edgeManifestPath = _writeEdgeManifest(
      fuzzDir: fuzzDir,
      packageName: packageName,
      sites: instrumentor.sites,
    );

    final dictionaryPath = p.join(fuzzDir, 'auto.dict');
    File(dictionaryPath)
        .writeAsStringSync(formatFuzzDictionary(instrumentor.dictionaryTokens));

    final overlayConfigPath = await _writeOverlayPackageConfig(
      rootDir: rootDir,
      packageName: packageName,
      fuzzDir: fuzzDir,
      additionalPackages: normalizedDeps.toSet(),
    );

    final result = (
      packageName: packageName,
      overlayPackageConfigPath: overlayConfigPath,
      edgeManifestPath: edgeManifestPath,
      dictionaryPath: dictionaryPath,
      instrumentedLibDir: instrumentedLibDir,
      filesInstrumented: filesInstrumented,
      edgesInserted: instrumentor.edgesInserted,
      comparesInserted: instrumentor.comparesInserted,
      switchesInserted: instrumentor.switchesInserted,
      dictionaryTokensExtracted: instrumentor.dictionaryTokens.length,
      cached: false,
    );
    _writeOverlayCache(cacheCtx, result);
    return result;
  }

  static Future<Map<String, String>> _computeOverlayInputFingerprints(
    String rootDir,
    String fuzzDir,
    File pkgConfigFile,
    Map<String, Directory> depLibDirs,
  ) async {
    final fuzzRoot = await _tryResolveFuzzPackageRoot();
    final fingerprints = <String, String>{
      'path:rootDir': rootDir,
      'path:fuzzDir': fuzzDir,
      'path:fuzzRoot': fuzzRoot ?? '',
      'pubspec.yaml': _fileStatToken(File(p.join(rootDir, 'pubspec.yaml'))),
      'pubspec.lock': _fileStatToken(File(p.join(rootDir, 'pubspec.lock'))),
      'package_config.json': _fileStatToken(pkgConfigFile),
    };
    _collectDirectoryFingerprints(
      Directory(p.join(rootDir, 'lib')),
      'lib',
      fingerprints,
    );
    for (final entry in depLibDirs.entries) {
      _collectDirectoryFingerprints(
        entry.value,
        'dep:${entry.key}',
        fingerprints,
      );
    }
    if (fuzzRoot != null) {
      _collectDirectoryFingerprints(
        Directory(p.join(fuzzRoot, 'lib')),
        'fuzz_self',
        fingerprints,
      );
    } else {
      fingerprints['executable'] = _fileStatToken(
        File(Platform.resolvedExecutable),
      );
    }
    return fingerprints;
  }

  static void _collectDirectoryFingerprints(
    Directory dir,
    String prefix,
    Map<String, String> out,
  ) {
    final dirPath = p.normalize(dir.path);
    final normalizedDir = Directory(dirPath);
    if (!normalizedDir.existsSync()) return;
    final stripLen = dirPath.endsWith(p.separator)
        ? dirPath.length
        : dirPath.length + 1;
    for (final entity in normalizedDir.listSync(recursive: true)) {
      if (entity is! File) continue;
      final rel = entity.path.substring(stripLen).replaceAll(r'\', '/');
      out['$prefix/$rel'] = _fileStatToken(entity);
    }
  }

  static String _fileStatToken(File file) {
    final stat = file.statSync();
    if (stat.type == FileSystemEntityType.notFound) return 'missing';
    return '${stat.size}:${stat.modified.microsecondsSinceEpoch}';
  }

  static OverlayResult? _tryLoadCachedOverlay(_OverlayCacheContext ctx) {
    final cachePath = p.join(ctx.fuzzDir, 'overlay_cache.json');
    final edgeManifestPath = p.join(ctx.fuzzDir, 'edge_manifest.json');
    final dictionaryPath = p.join(ctx.fuzzDir, 'auto.dict');
    final overlayConfigPath = p.join(ctx.fuzzDir, 'package_config.json');
    final instrumentedRoot = p.join(ctx.fuzzDir, 'instrumented');
    final requiredFiles = [
      cachePath,
      edgeManifestPath,
      dictionaryPath,
      overlayConfigPath,
    ];
    if (requiredFiles.any((path) => !File(path).existsSync()) ||
        !_hasAllInstrumentedOutputs(instrumentedRoot, ctx.inputFingerprints)) {
      return null;
    }
    try {
      final raw = jsonDecode(
        File(cachePath).readAsStringSync(),
      ) as Map<String, Object?>;
      if (raw['version'] != _overlayCacheVersion ||
          raw['packageName'] != ctx.packageName ||
          raw['runtimeImport'] != ctx.runtimeImport) {
        return null;
      }
      final cachedDeps = (raw['additionalPackages'] as List<Object?>)
          .cast<String>();
      final cachedInputs = (raw['inputs'] as Map<String, Object?>)
          .cast<String, String>();
      if (!_stringListsEqual(cachedDeps, ctx.normalizedDeps) ||
          !_stringMapsEqual(cachedInputs, ctx.inputFingerprints)) {
        return null;
      }
      return (
        packageName: ctx.packageName,
        overlayPackageConfigPath: overlayConfigPath,
        edgeManifestPath: edgeManifestPath,
        dictionaryPath: dictionaryPath,
        instrumentedLibDir: p.join(instrumentedRoot, 'lib'),
        filesInstrumented: raw['filesInstrumented'] as int,
        edgesInserted: raw['edgesInserted'] as int,
        comparesInserted: raw['comparesInserted'] as int,
        switchesInserted: raw['switchesInserted'] as int,
        dictionaryTokensExtracted: raw['dictionaryTokensExtracted'] as int,
        cached: true,
      );
    } on Object {
      return null;
    }
  }

  static bool _hasAllInstrumentedOutputs(
    String instrumentedRoot,
    Map<String, String> inputFingerprints,
  ) {
    for (final key in inputFingerprints.keys) {
      if (key.startsWith('lib/')) {
        if (!File(p.join(instrumentedRoot, key)).existsSync()) return false;
      } else if (key.startsWith('dep:')) {
        final slash = key.indexOf('/');
        final depName = key.substring(4, slash);
        final rel = key.substring(slash + 1);
        final path = p.join(instrumentedRoot, depName, 'lib', rel);
        if (!File(path).existsSync()) return false;
      }
    }
    return true;
  }

  static bool _stringListsEqual(List<String> a, List<String> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static bool _stringMapsEqual(Map<String, String> a, Map<String, String> b) {
    if (a.length != b.length) return false;
    for (final entry in a.entries) {
      if (b[entry.key] != entry.value) return false;
    }
    return true;
  }

  static void _writeOverlayCache(
    _OverlayCacheContext ctx,
    OverlayResult result,
  ) {
    final cachePath = p.join(ctx.fuzzDir, 'overlay_cache.json');
    final payload = <String, Object?>{
      'version': _overlayCacheVersion,
      'packageName': result.packageName,
      'runtimeImport': ctx.runtimeImport,
      'additionalPackages': ctx.normalizedDeps,
      'filesInstrumented': result.filesInstrumented,
      'edgesInserted': result.edgesInserted,
      'comparesInserted': result.comparesInserted,
      'switchesInserted': result.switchesInserted,
      'dictionaryTokensExtracted': result.dictionaryTokensExtracted,
      'inputs': ctx.inputFingerprints,
    };
    File(cachePath)
        .writeAsStringSync(const JsonEncoder.withIndent('  ').convert(payload));
  }

  static Directory _resolveDependencyLibDir(
    List<Map<String, Object?>> packages,
    String depName,
    String configDir,
  ) {
    for (final entry in packages) {
      if (entry['name'] != depName) continue;
      final absEntry = _absolutizePackageEntry(entry, configDir);
      final pkgRootPath = p.fromUri(Uri.parse(absEntry['rootUri'] as String));
      final pkgUriStr = (absEntry['packageUri'] as String?) ?? 'lib/';
      final libDir = Directory(
        p.normalize(p.join(pkgRootPath, p.fromUri(Uri.parse(pkgUriStr)))),
      );
      if (!libDir.existsSync()) {
        throw ArgumentError(
          'Dependency package "$depName" lib directory not found: '
          '${libDir.path}',
        );
      }
      return libDir;
    }
    throw ArgumentError(
      'Dependency package "$depName" not found in package_config.json.',
    );
  }

  static String _writeEdgeManifest({
    required String fuzzDir,
    required String packageName,
    required List<FuzzSiteEntry> sites,
  }) {
    final manifestPath = p.join(fuzzDir, 'edge_manifest.json');
    final payload = <String, Object?>{
      'package': packageName,
      'totalSites': sites.length,
      'sites': [
        for (final s in sites)
          {
            'id': s.id,
            'file': s.file,
            'line': s.line,
            'column': s.column,
            'kind': s.kind,
          },
      ],
    };
    File(manifestPath)
        .writeAsStringSync(const JsonEncoder.withIndent('  ').convert(payload));
    return manifestPath;
  }

  static String _extractPackageName(String pubspecContent) {
    final match = RegExp(
      r'^name:\s*([a-zA-Z0-9_]+)',
      multiLine: true,
    ).firstMatch(pubspecContent);
    if (match == null) {
      throw const FormatException('Could not parse `name:` from pubspec.yaml');
    }
    return match.group(1)!;
  }

  static int _instrumentDirectoryTree({
    required Directory sourceLibDir,
    required String instrumentedLibDir,
    required AstInstrumentor instrumentor,
    required String runtimeImport,
    String filePrefix = 'lib',
  }) {
    final files =
        sourceLibDir.listSync(recursive: true).whereType<File>().toList()
          ..sort((a, b) => a.path.compareTo(b.path));
    var count = 0;
    for (final entity in files) {
      final relPath = p.relative(entity.path, from: sourceLibDir.path);
      final destPath = p.join(instrumentedLibDir, relPath);
      Directory(p.dirname(destPath)).createSync(recursive: true);
      if (relPath.endsWith('.dart')) {
        final source = entity.readAsStringSync();
        final posixRel = p.posix.joinAll([filePrefix, ...p.split(relPath)]);
        final out = instrumentor.instrumentSource(
          source,
          runtimeImport: runtimeImport,
          filePath: posixRel,
        );
        File(destPath).writeAsStringSync(out);
        count++;
      } else {
        entity.copySync(destPath);
      }
    }
    return count;
  }

  static Future<String> _writeOverlayPackageConfig({
    required String rootDir,
    required String packageName,
    required String fuzzDir,
    required Set<String> additionalPackages,
  }) async {
    final pkgConfigFile = _findPackageConfigFile(rootDir);
    final rawJson =
        jsonDecode(pkgConfigFile.readAsStringSync()) as Map<String, Object?>;
    final configDir = p.dirname(pkgConfigFile.path);
    final packages = (rawJson['packages'] as List<Object?>)
        .cast<Map<String, Object?>>();
    final instrumentedRoot = p.join(fuzzDir, 'instrumented');

    final updatedPackages = <Map<String, Object?>>[];
    final presentNames = <String>{};

    for (final entry in packages) {
      final name = entry['name'] as String;
      presentNames.add(name);
      if (name == packageName) {
        updatedPackages.add(
          _buildRootPackageEntry(entry, rootDir, instrumentedRoot),
        );
      } else if (additionalPackages.contains(name)) {
        updatedPackages.add({
          ...entry,
          'rootUri': p.toUri(p.join(instrumentedRoot, name)).toString(),
          'packageUri': 'lib/',
        });
      } else {
        updatedPackages.add(_absolutizePackageEntry(entry, configDir));
      }
    }

    await _injectMissingRuntimePackages(updatedPackages, presentNames);

    final overlayConfigPath = p.join(fuzzDir, 'package_config.json');
    final overlayMap = <String, Object?>{
      ...rawJson,
      'packages': updatedPackages,
    };
    File(
      overlayConfigPath,
    ).writeAsStringSync(const JsonEncoder.withIndent('  ').convert(overlayMap));
    return overlayConfigPath;
  }

  static const _runtimeDependencies = ['fuzz', 'stack_trace', 'path'];

  static Future<void> _injectMissingRuntimePackages(
    List<Map<String, Object?>> updatedPackages,
    Set<String> presentNames,
  ) async {
    if (_runtimeDependencies.every(presentNames.contains)) return;
    final fuzzRoot = await _resolveFuzzPackageRoot();
    if (!presentNames.contains('fuzz')) {
      updatedPackages.add({
        'name': 'fuzz',
        'rootUri': p.toUri(fuzzRoot).toString(),
        'packageUri': 'lib/',
        'languageVersion': _resolveFuzzLanguageVersion(fuzzRoot),
      });
    }
    for (final depName in const ['stack_trace', 'path']) {
      if (presentNames.contains(depName)) continue;
      final depRoot = await _resolveRuntimeDepRoot(depName, fuzzRoot);
      if (depRoot == null) continue;
      updatedPackages.add({
        'name': depName,
        'rootUri': p.toUri(depRoot).toString(),
        'packageUri': 'lib/',
        'languageVersion': _resolveFuzzLanguageVersion(depRoot),
      });
    }
  }

  static Future<String?> _resolveRuntimeDepRoot(
    String depName,
    String fuzzRoot,
  ) async {
    final resolved = await Isolate.resolvePackageUri(
      Uri.parse('package:$depName/$depName.dart'),
    );
    if (resolved != null) {
      final root = p.dirname(p.dirname(resolved.toFilePath()));
      if (File(p.join(root, 'lib', '$depName.dart')).existsSync()) return root;
    }
    final fuzzConfig = File(
      p.join(fuzzRoot, '.dart_tool', 'package_config.json'),
    );
    if (fuzzConfig.existsSync()) {
      final raw =
          jsonDecode(fuzzConfig.readAsStringSync()) as Map<String, Object?>;
      final configDir = p.dirname(fuzzConfig.path);
      final pkgs = (raw['packages'] as List<Object?>)
          .cast<Map<String, Object?>>();
      for (final entry in pkgs) {
        if (entry['name'] != depName) continue;
        final abs = _absolutizePackageEntry(entry, configDir);
        return p.fromUri(Uri.parse(abs['rootUri'] as String));
      }
    }
    return _findPackageInPubCache(
      '$depName-',
      validate: (d) => File(p.join(d, 'lib', '$depName.dart')).existsSync(),
    );
  }

  static Map<String, Object?> _buildRootPackageEntry(
    Map<String, Object?> entry,
    String rootDir,
    String instrumentedRoot,
  ) {
    final instrumentedLibDir = p.join(instrumentedRoot, 'lib');
    if (p.isWithin(rootDir, instrumentedLibDir)) {
      final relPosix = p.posix.joinAll(
        p.split(p.relative(instrumentedLibDir, from: rootDir)),
      );
      return {
        ...entry,
        'rootUri': p.toUri(rootDir).toString(),
        'packageUri': '$relPosix/',
      };
    }
    return {
      ...entry,
      'rootUri': p.toUri(instrumentedRoot).toString(),
      'packageUri': 'lib/',
    };
  }

  static String _resolveFuzzLanguageVersion(String fuzzRoot) {
    final pubspec = File(p.join(fuzzRoot, 'pubspec.yaml'));
    if (pubspec.existsSync()) {
      final match = RegExp(r'sdk:\s*["\x27]?(?:\^|>=)?(\d+\.\d+)')
          .firstMatch(pubspec.readAsStringSync());
      if (match != null) return match.group(1)!;
    }
    final vmMatch = RegExp(r'^(\d+\.\d+)').firstMatch(Platform.version);
    return vmMatch?.group(1) ?? '3.7';
  }

  static File _findPackageConfigFile(String startDir) {
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

  static Map<String, Object?> _absolutizePackageEntry(
    Map<String, Object?> entry,
    String configDir,
  ) {
    final rootUriStr = entry['rootUri'] as String;
    final parsed = Uri.parse(rootUriStr);
    if (parsed.hasScheme) return entry;
    final absPath = p.normalize(p.join(configDir, p.fromUri(parsed)));
    return {...entry, 'rootUri': p.toUri(absPath).toString()};
  }

  static Future<String> _resolveFuzzPackageRoot() async {
    final resolved = await _tryResolveFuzzPackageRoot();
    if (resolved != null) return resolved;
    throw StateError(
      'Unable to locate package:fuzz root directory for child VM overlay. '
      'Set FUZZ_PACKAGE_ROOT or install package:fuzz in PUB_CACHE.',
    );
  }

  static Future<String?> _tryResolveFuzzPackageRoot() async {
    final resolved = await Isolate.resolvePackageUri(
      Uri.parse('package:fuzz/fuzz.dart'),
    );
    if (resolved != null) {
      final root = p.dirname(p.dirname(resolved.toFilePath()));
      if (_isValidFuzzRoot(root)) return root;
    }
    final envRoot = Platform.environment['FUZZ_PACKAGE_ROOT'];
    if (envRoot != null && envRoot.isNotEmpty && _isValidFuzzRoot(envRoot)) {
      return p.normalize(p.absolute(envRoot));
    }
    for (final start in [
      Directory.current.path,
      p.dirname(Platform.resolvedExecutable),
    ]) {
      final found = _walkUpForFuzzRoot(start);
      if (found != null) return found;
    }
    return _findPackageInPubCache('fuzz', validate: _isValidFuzzRoot);
  }

  static bool _isValidFuzzRoot(String dir) =>
      File(p.join(dir, 'lib', 'src', 'fuzz_runtime.dart')).existsSync();

  static String? _walkUpForFuzzRoot(String startDir) {
    var cur = p.normalize(p.absolute(startDir));
    while (true) {
      if (_isValidFuzzRoot(cur)) return cur;
      final parent = p.dirname(cur);
      if (parent == cur) return null;
      cur = parent;
    }
  }

  static String? _findPackageInPubCache(
    String prefix, {
    required bool Function(String) validate,
  }) {
    final cacheRoot =
        Platform.environment['PUB_CACHE'] ??
        p.join(
          Platform.environment['HOME'] ??
              Platform.environment['USERPROFILE'] ??
              '',
          '.pub-cache',
        );
    for (final sub in [p.join('hosted', 'pub.dev'), 'git']) {
      final dir = Directory(p.join(cacheRoot, sub));
      if (!dir.existsSync()) continue;
      final matches =
          dir
              .listSync()
              .whereType<Directory>()
              .where((d) => p.basename(d.path).startsWith(prefix))
              .where((d) => validate(d.path))
              .toList()
            ..sort((a, b) => b.path.compareTo(a.path));
      if (matches.isNotEmpty) return matches.first.path;
    }
    return null;
  }
}
