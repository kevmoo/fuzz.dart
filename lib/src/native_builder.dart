import 'dart:io';
import 'dart:isolate';

import 'package:path/path.dart' as p;

/// Thrown when `--mode=cgf` is requested but `clang++` or LLVM `compiler-rt`
/// (`libclang_rt.fuzzer_no_main`) is unavailable on the host machine.
class ToolchainMissingException implements Exception {
  final String details;

  const ToolchainMissingException(this.details);

  @override
  String toString() =>
      'ERROR: Coverage-guided fuzzing (--mode=cgf) requires clang++ with '
      'LLVM libFuzzer (compiler-rt).\n'
      'Details: $details\n\n'
      'Install clang/LLVM:\n'
      '  • Ubuntu/Debian: sudo apt-get install -y clang llvm libclang-rt-dev\n'
      '  • macOS (Homebrew): brew install llvm && '
      'export PATH="\$(brew --prefix llvm)/bin:\$PATH"\n\n'
      'Or explicitly re-run using the pure-Dart engine without clang++:\n'
      '  dart run fuzz run --mode=pure-dart <target.dart>';
}

/// Locates `clang++` and compiles `fuzzer.cc` into a shared library linked
/// against LLVM's `libclang_rt.fuzzer_no_main`.
class NativeFuzzerBuilder {
  static const List<String> _clangCandidates = [
    'clang++',
    'clang++-21',
    'clang++-20',
    'clang++-19',
    'clang++-18',
    'clang++-17',
    'clang++-16',
    'clang++-15',
  ];

  static const List<String> _fuzzerArchiveCandidates = [
    'libclang_rt.fuzzer_no_main-x86_64.a',
    'libclang_rt.fuzzer_no_main-aarch64.a',
    'libclang_rt.fuzzer_no_main.a',
    'libclang_rt.fuzzer_no_main_osx.a',
  ];

  /// Resolves the `clang++` executable from `CLANG_CXX` or `PATH`, preferring
  /// a toolchain that provides `libclang_rt.fuzzer_no_main`, or returns `null`
  /// if none is installed.
  static String? findClangExecutable({Map<String, String>? environment}) {
    final env = environment ?? Platform.environment;
    final explicit = env['CLANG_CXX'];
    if (explicit != null && explicit.isNotEmpty) {
      return _isRunnableCompiler(explicit) ? explicit : null;
    }
    String? firstRunnable;
    for (final candidate in _clangCandidates) {
      if (!_isRunnableCompiler(candidate)) continue;
      firstRunnable ??= candidate;
      if (_locateFuzzerNoMainArchive(candidate) != null) {
        return candidate;
      }
    }
    return firstRunnable;
  }

  static bool _isRunnableCompiler(String executable) {
    try {
      final result = Process.runSync(executable, const ['--version']);
      return result.exitCode == 0;
    } on ProcessException {
      return false;
    }
  }

  /// Embedded copy of `lib/src/native/fuzzer.cc` used when running from an
  /// AOT-compiled executable (`dart install`) where `Isolate.resolvePackageUri`
  /// is unavailable.
  static const String embeddedFuzzerCc = r'''
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <utility>

using DartFuzzCallback = int (*)(const uint8_t* Data, size_t Size);
static DartFuzzCallback g_dart_callback = nullptr;
static const uint8_t* g_site_hits = nullptr;
static size_t g_site_hits_size = 0;
static bool g_atexit_registered = false;

static void FlushSiteHitsAtExit() {
  if (g_site_hits == nullptr || g_site_hits_size == 0) return;
  const char* path = std::getenv("FUZZ_SITE_HITS_PATH");
  if (path == nullptr || path[0] == '\0') return;
  FILE* fp = std::fopen(path, "wb");
  if (fp == nullptr) return;
  std::fwrite(g_site_hits, 1, g_site_hits_size, fp);
  std::fclose(fp);
}

extern "C" {

// Provided by libFuzzer (LLVM compiler-rt).
extern void __sanitizer_cov_8bit_counters_init(uint8_t* Start, uint8_t* Stop);
extern void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2);
extern void __sanitizer_weak_hook_memcmp(void* caller_pc, const void* s1,
                                         const void* s2, size_t n, int result);
extern int LLVMFuzzerRunDriver(int* argc, char*** argv,
                               int (*UserCb)(const uint8_t* Data, size_t Size));

}  // extern "C"

namespace {

volatile uint32_t g_pc_sink = 0;

template <size_t I>
__attribute__((noinline)) void TraceCmp8Slot(uint64_t arg1, uint64_t arg2) {
  __sanitizer_cov_trace_cmp8(arg1, arg2);
  // Post-call volatile write of distinct immediate `I`:
  // 1. Prevents tail-call optimization (`jmp`), ensuring `call` pushes a
  //    return address onto the stack for `__builtin_return_address(0)`.
  // 2. Makes each instantiation's machine code unique so linker Identical Code
  //    Folding (--icf) cannot collapse the 512 slots into one function.
  g_pc_sink = static_cast<uint32_t>(I);
}

template <size_t... Is>
constexpr std::array<void (*)(uint64_t, uint64_t), sizeof...(Is)>
MakeTraceCmp8Table(std::index_sequence<Is...>) {
  return {&TraceCmp8Slot<Is>...};
}

constexpr auto kTraceCmp8Table =
    MakeTraceCmp8Table(std::make_index_sequence<512>{});

}  // namespace

extern "C" {

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  if (g_dart_callback != nullptr) {
    return g_dart_callback(Data, Size);
  }
  return 0;
}

uint8_t* AllocateCounters(size_t size) {
  return static_cast<uint8_t*>(calloc(1, size));
}

void RegisterDartCounters(uint8_t* Start, size_t Size) {
  __sanitizer_cov_8bit_counters_init(Start, Start + Size);
}

void RegisterSiteHits(const uint8_t* Start, size_t Size) {
  g_site_hits = Start;
  g_site_hits_size = Size;
  if (!g_atexit_registered) {
    std::atexit(FlushSiteHitsAtExit);
    g_atexit_registered = true;
  }
}

void TraceCmp8(uint64_t Arg1, uint64_t Arg2) {
  __sanitizer_cov_trace_cmp8(Arg1, Arg2);
}

// Disambiguates caller PC across up to 512 comparison sites for libFuzzer's
// ValueProfileMap while also feeding TORC8 (Table of Recent Compares).
void TraceCmp8WithPc(uint64_t Arg1, uint64_t Arg2, uint64_t FakePc) {
  kTraceCmp8Table[FakePc & 0x1FFu](Arg1, Arg2);
}

void TraceMemcmp(uint64_t CallerPc, const uint8_t* S1, const uint8_t* S2,
                 size_t N, int Result) {
  __sanitizer_weak_hook_memcmp(reinterpret_cast<void*>(CallerPc), S1, S2, N,
                               Result);
}

int StartFuzzerWithArgs(DartFuzzCallback callback, int argc, char** argv) {
  g_dart_callback = callback;
  return LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}

}  // extern "C"
''';

  /// Resolves the path to `lib/src/native/fuzzer.cc` inside `package:fuzz`,
  /// materializing [embeddedFuzzerCc] into [fallbackOutputDir] when running
  /// from an AOT-compiled executable.
  static Future<String> resolveFuzzerCcPath({String? fallbackOutputDir}) async {
    final packageUri = Uri.parse('package:fuzz/src/native/fuzzer.cc');
    final resolved = await Isolate.resolvePackageUri(packageUri);
    if (resolved != null) {
      final path = resolved.toFilePath();
      if (File(path).existsSync()) return path;
    }
    final fallback = p.join('lib', 'src', 'native', 'fuzzer.cc');
    if (File(fallback).existsSync()) return p.normalize(p.absolute(fallback));
    if (fallbackOutputDir != null && fallbackOutputDir.isNotEmpty) {
      Directory(fallbackOutputDir).createSync(recursive: true);
      final materialized = p.normalize(
        p.absolute(p.join(fallbackOutputDir, 'fuzzer.cc')),
      );
      File(materialized).writeAsStringSync(embeddedFuzzerCc);
      return materialized;
    }
    throw StateError('Unable to locate package:fuzz/src/native/fuzzer.cc');
  }

  /// Compiles `fuzzer.cc` into [outputDir] and returns the absolute path to the
  /// resulting shared library (`libfuzzer_dart.so` or `libfuzzer_dart.dylib`).
  ///
  /// Throws [ToolchainMissingException] if `clang++` or `compiler-rt` is not
  /// available.
  static Future<String> buildSharedLibrary({
    required String outputDir,
    String? clangExecutable,
    bool forceRebuild = false,
  }) async {
    final clang = clangExecutable ?? findClangExecutable();
    if (clang == null || !_isRunnableCompiler(clang)) {
      final label = clang ?? 'PATH / CLANG_CXX';
      throw ToolchainMissingException(
        'No runnable clang++ executable found ($label).',
      );
    }

    final ext = Platform.isMacOS ? 'dylib' : 'so';
    final outPath = p.normalize(
      p.absolute(p.join(outputDir, 'libfuzzer_dart.$ext')),
    );
    final srcPath = await resolveFuzzerCcPath(fallbackOutputDir: outputDir);
    final outFile = File(outPath);
    if (!forceRebuild &&
        outFile.existsSync() &&
        !outFile.lastModifiedSync().isBefore(
          File(srcPath).lastModifiedSync(),
        )) {
      return outPath;
    }

    Directory(outputDir).createSync(recursive: true);
    final archive = _locateFuzzerNoMainArchive(clang);
    final args = _buildCompileArgs(
      srcPath: srcPath,
      outPath: outPath,
      archivePath: archive,
    );

    final res = Process.runSync(clang, args);
    if (res.exitCode != 0) {
      throw ToolchainMissingException(
        'Command `$clang ${args.join(' ')}` exited with ${res.exitCode}:\n'
        '${res.stderr}',
      );
    }
    return outPath;
  }

  static String? _locateFuzzerNoMainArchive(String clang) {
    for (final name in _fuzzerArchiveCandidates) {
      final res = Process.runSync(clang, ['-print-file-name=$name']);
      if (res.exitCode != 0) continue;
      final candidate = (res.stdout as String).trim();
      if (candidate.isNotEmpty &&
          candidate != name &&
          File(candidate).existsSync()) {
        return candidate;
      }
    }
    return null;
  }

  static List<String> _buildCompileArgs({
    required String srcPath,
    required String outPath,
    required String? archivePath,
  }) {
    if (archivePath == null) {
      throw const ToolchainMissingException(
        'Could not locate libclang_rt.fuzzer_no_main archive via '
        '`clang++ -print-file-name`.',
      );
    }
    return [
      '-O2',
      '-std=c++17',
      if (Platform.isMacOS) '-dynamiclib' else '-shared',
      '-fPIC',
      srcPath,
      archivePath,
      '-o',
      outPath,
    ];
  }
}
