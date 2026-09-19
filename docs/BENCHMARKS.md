# Benchmarks

What `nd7 record` and `nd7 verify` cost, measured 2026-09-19 on an Apple M1
Pro (10 cores, 16 GB, macOS Darwin 25.6.0 arm64), release build, frames of
1507 bytes.

Method: the harness is [bench/record_verify.py](../bench/record_verify.py). It
builds one session per size under a private `XDG_STATE_HOME` by looping
`nd7 record`, one process per frame, with a ~1.5 KB `PreToolUse` payload for
`Bash`; then it times each target with `subprocess.run` wrapped in
`time.perf_counter_ns()` and reports the median and p99 of the per-iteration
samples. The `record` runs are interleaved round-robin with a `/usr/bin/true`
sample in every round, so drift in the machine hits every target equally and
the `true` median is a spawn baseline measured under the same conditions; a
block-ordered run of the same work shows a drift between the first block and
the last that is not in the code. "Net of spawn" is a target's median minus
that baseline.

## record vs log size

Interleaved, 200 samples per target.

| target | median | p99 | net of spawn |
| --- | --- | --- | --- |
| `/usr/bin/true` | 3.404 ms | 9.130 ms | — |
| record, 1,000 frames | 5.005 ms | 11.777 ms | 1.600 ms |
| record, 10,000 frames | 5.009 ms | 8.254 ms | 1.605 ms |
| record, 50,000 frames | 5.026 ms | 10.842 ms | 1.622 ms |

Fresh session, measured as a block rather than interleaved because it cannot
be interleaved with itself, and including the `mkdir` of the session
directory: 4.960 ms median, 11.144 ms p99, 1.725 ms net of spawn.

`record` is O(1) in log size: over a 50× growth the median moves by 22 µs,
which is inside the noise. That is the `head` sidecar and the backwards tail
read doing their job — an append reads one frame and one small file, never the
log. About 68% of a hook's wall time is process creation, which nd7 cannot
influence; the part that is ours is ~1.6 ms.

## record under contention

50 `nd7 record` processes spawned against the 10,000-frame session, then given
their stdin, then waited on.

- total wall: 98.3 ms, 1.97 ms per process amortized
- all 50 exited 0, every stderr empty
- frames 10,205 → 10,255: delta exactly 50, so no append was lost or doubled
- `nd7 verify` on the session afterwards: clean

The advisory lock serializes the appends without anyone failing, and the
amortized cost per process is below the single-process figure because the
spawns overlap.

## verify vs log size

20 runs each, median of the per-run samples.

| session | frames | bytes | median | p99 | MB/s | µs/frame |
| --- | --- | --- | --- | --- | --- | --- |
| 1k | 1,205 | 1,814,825 | 8.201 ms | 10.300 ms | 221.3 | 6.81 |
| 10k | 10,205 | 15,388,235 | 36.003 ms | 37.445 ms | 427.4 | 3.53 |
| 50k | 50,205 | 75,748,235 | 161.018 ms | 169.102 ms | 470.4 | 3.21 |

Linear in bytes. The low MB/s at 1k is fixed process-spawn cost spread over a
small file, not a different algorithm: net of spawn the three are ~363 MB/s at
1k against ~480 MB/s at 50k, converging.

### Where verify's time goes

Measured against the 50k log (75.7 MB):

- `cat` of the file: 22.4 ms. That is the I/O floor.
- BLAKE3 over the whole file as one buffer: 45 ms, 1,538 MB/s, which is the
  multi-chunk SIMD path.
- BLAKE3 over 50,000 separate 1,507-byte frames, the way `verify` actually
  hashes — two `Hasher` updates and a hex comparison per frame: 98 ms,
  768 MB/s, 1.96 µs per frame. This number came from a throwaway crate that
  hashed 50,000 1.5 KB buffers with `Hasher::update(prefix).update(b"}")`, not
  from nd7 itself.

So the 161 ms splits roughly into ~22 ms of I/O, ~98 ms of hashing, and ~40 ms
of line splitting, field search and comparisons. Hashing dominates, and
per-frame hashing costs half the throughput of one big buffer because each
frame is too small for the multi-chunk path. The only remaining lever is
checking frames on several cores, which `check_frame` is already shaped for:
it depends on nothing but one line's bytes and the previous line's claimed
hash. Not pulled yet — 161 ms per 50,000 frames is fast enough for a command a
human runs.

## record error paths

200 runs each. A hook that cannot parse its input must still be cheap, must
not block the agent, and must say one thing about it.

| input | median | p99 | net of spawn | exit | stderr |
| --- | --- | --- | --- | --- | --- |
| malformed (`nope`) | 4.555 ms | 12.950 ms | 1.319 ms | 0 | exactly 1 line |
| empty stdin | 4.719 ms | 14.688 ms | 1.484 ms | 0 | exactly 1 line |

Both are slightly cheaper than a successful record, which is what it should
be: the parse fails before anything is written.

## How to rerun

```sh
cargo build --release
python3 bench/record_verify.py                       # 1k, 10k and 50k, 200 iterations
python3 bench/record_verify.py --sizes 1000 --iters 50   # a quick pass
```

The script needs nothing but Python 3 and the release binary, and it works in
a private `XDG_STATE_HOME` under a temp directory which it removes at exit
unless `--keep` is given. Building the 50,000-frame session is the slow part,
about five minutes, because every frame is one process.

All numbers here are for a **release** build. The binary installed as a hook
during development is a debug build and is roughly 1 ms slower per invocation;
that difference is not measured here.
