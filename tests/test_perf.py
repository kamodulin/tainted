# To see the output of this test run `python3 tests/test_perf.py`

import time
import tracemalloc

from tainted import _function_sink, _make_taintable, _taint


def print_results(test_name, reference_time, tainted_time):
    print(
        f"{test_name}: "
        f"reference: {reference_time:.3f}s, "
        f"tainted: {tainted_time:.3f}s, "
        f"tainted/reference ratio: {tainted_time / reference_time:.2f}x"
    )


def test_speed():
    NUM_ITERATIONS = 100_000

    print("Running speed tests...")

    start_time = time.time()
    x, y, z = 1, 2, 3
    for _ in range(NUM_ITERATIONS):
        x = 2 * x + y - z
    end_time = time.time()
    reference_time = end_time - start_time

    start_time = time.time()
    x, y, z = _taint(1), _taint(2), _taint(3)
    for _ in range(NUM_ITERATIONS):
        x = 2 * x + y - z
    end_time = time.time()
    tainted_time = end_time - start_time

    print_results("Basic operation speed test", reference_time, tainted_time)

    start_time = time.time()
    s = {1, 2, 3}
    for _ in range(NUM_ITERATIONS):
        s.add(1)
    end_time = time.time()
    reference_time = end_time - start_time

    start_time = time.time()
    s = _make_taintable({1, 2, 3})
    for _ in range(NUM_ITERATIONS):
        s.add(1)
    end_time = time.time()
    tainted_time = end_time - start_time

    print_results("Method call speed test", reference_time, tainted_time)

    def f(x, y, z):
        return 2 * x + y - z

    start_time = time.time()
    x, y, z = 1, 2, 3
    for _ in range(NUM_ITERATIONS):
        x = f(x, y, z)
    end_time = time.time()
    reference_time = end_time - start_time

    start_time = time.time()
    x, y, z = 1, 2, 3
    for _ in range(NUM_ITERATIONS):
        x = _function_sink(f, x, y, z)
    end_time = time.time()
    tainted_time = end_time - start_time

    print_results("Function call speed test", reference_time, tainted_time)


def test_memory_usage():
    NUM_ITERATIONS = 10_000

    print("Running memory usage tests...")

    tracemalloc.start()
    l = []
    x, y, z = 1, 2, 3
    for _ in range(NUM_ITERATIONS):
        l.append(2 * x + y - z)
    reference_size, reference_peak = tracemalloc.get_traced_memory()

    tracemalloc.start()
    l = []
    x, y, z = _taint(1), _taint(2), _taint(3)
    for _ in range(NUM_ITERATIONS):
        l.append(2 * x + y - z)
    tainted_size, tainted_peak = tracemalloc.get_traced_memory()

    print(
        f"Basic addition memory test: "
        f"reference (size): {reference_size / 1024:.1f} KiB, "
        f"reference (peak): {reference_peak / 1024:.1f} KiB, "
        f"tainted (size): {tainted_size / 1024:.1f} KiB, "
        f"tainted (peak): {tainted_peak / 1024:.1f} KiB, "
        f"tainted/reference ratio: {tainted_peak / reference_peak:.2f}x"
    )


if __name__ == "__main__":
    test_speed()
    test_memory_usage()
