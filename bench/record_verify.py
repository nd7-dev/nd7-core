#!/usr/bin/env python3
"""What `nd7 record` and `nd7 verify` cost, measured end to end.

Four sections, printed as Markdown tables:

1. `record` against log size. Every round measures one `/usr/bin/true` spawn
   and one `record` into each session, round-robin, so machine drift hits all
   targets equally; a block-ordered run shows a spurious drift between the
   first block and the last. The `true` median is the process-creation floor,
   and "net of spawn" is what nd7 itself adds. A fresh session (empty, created
   by the first append) is measured separately, as one block, since it cannot
   be interleaved with itself.
2. `record` under contention: 50 processes appending to one session at once.
   Checks the advisory lock: every append lands, none fails, the chain stays
   verifiable.
3. `verify` against log size: bytes on disk, MB/s, microseconds per frame.
4. `record` error paths: malformed JSON and empty stdin must cost about the
   same, exit 0, and say one thing on stderr.

Every frame is ~1.5 KB, the size of a real `PreToolUse` payload for `Bash`.
Sessions are built by looping `nd7 record`, one process per frame, so building
the 50,000-frame session takes about five minutes.

Run:

    cargo build --release && python3 bench/record_verify.py [--sizes 1000,10000,50000] [--iters 200] [--keep]

The logs go into a private XDG_STATE_HOME under a fresh temp directory, which
is removed at exit unless --keep is given.
"""

import argparse
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "target" / "release" / "nd7"
WARMUP = 5
CONCURRENCY = 50
VERIFY_RUNS = 20


def payload(session_id):
    """One hook payload, ~1.5 KB on disk once the envelope is around it."""
    return json.dumps(
        {
            "session_id": session_id,
            "transcript_path": "/t",
            "cwd": "/p",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls", "description": "f" * 1000},
            "tool_use_id": "t1",
        }
    ).encode()


def stats(samples):
    """Median and p99 of a sample list, both in the sample's own unit."""
    ordered = sorted(samples)
    p99 = ordered[max(0, math.ceil(0.99 * len(ordered)) - 1)]
    return statistics.median(ordered), p99


def run(argv, env, stdin=b""):
    """One subprocess, timed around `subprocess.run`. Returns (ms, result)."""
    started = time.perf_counter_ns()
    done = subprocess.run(argv, input=stdin, env=env, capture_output=True)
    return (time.perf_counter_ns() - started) / 1e6, done


def build_session(env, session, frames):
    """Append `frames` frames to `session`, one `nd7 record` process each."""
    print(f"building {session}: {frames} frames", flush=True)
    data = payload(session)
    for i in range(frames):
        if i and i % 10_000 == 0:
            print(f"  {i}/{frames}", flush=True)
        _, done = run([str(BIN), "record"], env, data)
        if done.returncode != 0 or done.stderr:
            sys.exit(f"record failed building {session}: {done.stderr.decode()}")


def bench_record(env, sessions, iters):
    """Section 1. Returns the `/usr/bin/true` median, the spawn floor in ms."""
    targets = [("/usr/bin/true", ["/usr/bin/true"], b"")]
    for frames, session in sessions:
        targets.append((f"record, {frames:,} frames", [str(BIN), "record"], payload(session)))

    samples = {label: [] for label, _, _ in targets}
    for _ in range(WARMUP):
        for _, argv, data in targets:
            run(argv, env, data)
    for _ in range(iters):
        for label, argv, data in targets:
            ms, done = run(argv, env, data)
            if done.returncode != 0 or done.stderr:
                sys.exit(f"{label} failed: {done.stderr.decode()}")
            samples[label].append(ms)

    spawn, _ = stats(samples["/usr/bin/true"])
    print(f"\n## record vs log size (interleaved, {iters} per size)\n")
    print("| target | median | p99 | net of spawn |")
    print("| --- | --- | --- | --- |")
    for label, _, _ in targets:
        median, p99 = stats(samples[label])
        net = "—" if label == "/usr/bin/true" else f"{median - spawn:.3f} ms"
        print(f"| {label} | {median:.3f} ms | {p99:.3f} ms | {net} |")

    fresh = f"fresh-{os.getpid()}"
    data = payload(fresh)
    block = []
    for _ in range(iters):
        ms, done = run([str(BIN), "record"], env, data)
        if done.returncode != 0 or done.stderr:
            sys.exit(f"fresh-session record failed: {done.stderr.decode()}")
        block.append(ms)
    median, p99 = stats(block)
    print(
        f"\nFresh session (measured as a block, not interleaved; the first record "
        f"creates the directory): {median:.3f} ms median, {p99:.3f} ms p99, "
        f"{median - spawn:.3f} ms net of spawn."
    )
    return spawn


def bench_contention(env, session):
    """Section 2: `CONCURRENCY` records into one session, all in flight."""
    events = Path(env["XDG_STATE_HOME"]) / "nd7" / "sessions" / session / "events.ndjson"
    before = sum(1 for _ in events.open("rb"))
    data = payload(session)

    started = time.perf_counter_ns()
    procs = [
        subprocess.Popen(
            [str(BIN), "record"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        for _ in range(CONCURRENCY)
    ]
    for p in procs:
        p.stdin.write(data)
        p.stdin.close()
    errs = [p.stderr.read().decode() for p in procs]
    codes = [p.wait() for p in procs]
    total = (time.perf_counter_ns() - started) / 1e6
    for p in procs:
        p.stdout.close()
        p.stderr.close()

    after = sum(1 for _ in events.open("rb"))
    _, verified = run([str(BIN), "verify", session], env)
    first = verified.stdout.decode().splitlines()[0] if verified.stdout else verified.stderr.decode().strip()

    print(f"\n## record under contention ({CONCURRENCY} concurrent, session {session})\n")
    print(f"- total wall: {total:.1f} ms ({total / CONCURRENCY:.2f} ms per process amortized)")
    print(f"- exit codes: {sorted(set(codes))}")
    print(f"- stderr: {'empty' if not any(errs) else errs}")
    print(f"- frames: {before:,} → {after:,} (delta {after - before})")
    print(f"- verify afterwards: `{first}` (exit {verified.returncode})")


def bench_verify(env, sessions):
    """Section 3: `verify` against log size."""
    print(f"\n## verify vs log size ({VERIFY_RUNS} runs, median)\n")
    print("| session | frames | bytes | median | p99 | MB/s | µs/frame |")
    print("| --- | --- | --- | --- | --- | --- | --- |")
    for frames, session in sessions:
        events = Path(env["XDG_STATE_HOME"]) / "nd7" / "sessions" / session / "events.ndjson"
        size = events.stat().st_size
        lines = sum(1 for _ in events.open("rb"))
        samples = []
        for _ in range(VERIFY_RUNS):
            ms, done = run([str(BIN), "verify", session], env)
            if done.returncode != 0:
                sys.exit(f"verify {session} failed: {done.stderr.decode()}")
            samples.append(ms)
        median, p99 = stats(samples)
        print(
            f"| {frames:,} | {lines:,} | {size:,} | {median:.3f} ms | {p99:.3f} ms "
            f"| {size / 1e6 / (median / 1e3):.1f} | {median * 1e3 / lines:.2f} |"
        )


def bench_errors(env, iters, spawn):
    """Section 4: a hook that cannot parse its input still must be cheap."""
    print(f"\n## record error paths ({iters} runs each)\n")
    print("| input | median | p99 | net of spawn | exit codes | stderr lines |")
    print("| --- | --- | --- | --- | --- | --- |")
    for label, data in [("malformed (`nope`)", b"nope"), ("empty stdin", b"")]:
        samples, codes, stderr_lines = [], set(), set()
        for _ in range(iters):
            ms, done = run([str(BIN), "record"], env, data)
            samples.append(ms)
            codes.add(done.returncode)
            stderr_lines.add(len(done.stderr.decode().splitlines()))
        median, p99 = stats(samples)
        print(
            f"| {label} | {median:.3f} ms | {p99:.3f} ms | {median - spawn:.3f} ms "
            f"| {sorted(codes)} | {sorted(stderr_lines)} |"
        )


def main():
    parser = argparse.ArgumentParser(description="measure nd7 record and verify")
    parser.add_argument("--sizes", default="1000,10000,50000", help="session sizes, comma separated")
    parser.add_argument("--iters", type=int, default=200, help="timed samples per target")
    parser.add_argument("--keep", action="store_true", help="keep the temp state directory")
    args = parser.parse_args()

    if not BIN.is_file():
        sys.exit(f"no binary at {BIN}: run `cargo build --release` first")
    sizes = sorted(int(s) for s in args.sizes.split(","))

    state = tempfile.mkdtemp(prefix="nd7-bench-")
    env = dict(os.environ, XDG_STATE_HOME=state)
    print("# nd7 record/verify benchmark\n")
    print(f"binary: `{BIN}`  \nstate: `{state}`  \nsizes: {sizes}, iters: {args.iters}\n")
    try:
        sessions = [(n, f"bench-{n}") for n in sizes]
        for frames, session in sessions:
            build_session(env, session, frames)
        spawn = bench_record(env, sessions, args.iters)
        # The middle session, so a default run contends on the 10,000-frame one.
        bench_contention(env, sessions[len(sessions) // 2][1])
        bench_verify(env, sessions)
        bench_errors(env, args.iters, spawn)
    finally:
        if args.keep:
            print(f"\nkept: {state}")
        else:
            shutil.rmtree(state, ignore_errors=True)


if __name__ == "__main__":
    main()
