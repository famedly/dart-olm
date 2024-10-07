// Import BenchmarkBase class.
import 'package:benchmark_harness/benchmark_harness.dart';

import 'dart:math';
import 'dart:typed_data';

// Create a new benchmark by extending BenchmarkBase
class SingleNumberRandomFillBenchmark extends BenchmarkBase {
  final int limit;
  SingleNumberRandomFillBenchmark(this.limit)
      : super('Benching numbers with limit $limit');

  final Random rng = Random.secure();

  // The benchmark code.
  @override
  void exercise() {
    //rng.nextInt(limit);
    Uint8List list = Uint8List(32 * 50);
    list.setAll(0, Iterable.generate(list.length, (i) => rng.nextInt(limit)));
  }

  // Not measured setup code executed prior to the benchmark runs.
  @override
  void setup() {}

  // Not measured teardown code executed after the benchmark runs.
  @override
  void teardown() {}

  // To opt into the reporting the time per run() instead of per 10 run() calls.
  //@override
  //void exercise() => run();
}

class BulkRandomFillBenchmark extends BenchmarkBase {
  final int limit;
  BulkRandomFillBenchmark(this.limit)
      : super('Generating bytes 4 at a time with limit $limit');

  final Random rng = Random.secure();

  // The benchmark code.
  @override
  void exercise() {
    //rng.nextInt(limit);
    Uint8List list = Uint8List(32 * 50);
    final temp = [0, 0, 0, 0];
    list.setAll(
        0,
        Iterable.generate(list.length, (i) {
          final pos = i % 4;
          if (pos == 0) {
            //final n = rng.nextInt(0x1000000);
            final n = rng.nextInt(limit);
            temp[0] = (0xff000000 & n) >> 24;
            temp[1] = (0xff0000 & n) >> 16;
            temp[2] = (0xff00 & n) >> 8;
            temp[3] = (0xff & n);
          }
          return temp[pos];
        }));
  }

  // Not measured setup code executed prior to the benchmark runs.
  @override
  void setup() {}

  // Not measured teardown code executed after the benchmark runs.
  @override
  void teardown() {}

  // To opt into the reporting the time per run() instead of per 10 run() calls.
  //@override
  //void exercise() => run();
}

void main() {
  // Run TemplateBenchmark
  SingleNumberRandomFillBenchmark(0xff).report();
  SingleNumberRandomFillBenchmark(0x100).report();
  SingleNumberRandomFillBenchmark(256).report();
  BulkRandomFillBenchmark(0xffffffff).report();
  BulkRandomFillBenchmark(0x100000000).report();
}
