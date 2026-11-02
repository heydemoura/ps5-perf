# ps5-perf

A `perf(1)`-style sampling profiler for the PlayStation 5, built as an
[elfldr](https://github.com/ps5-payload-dev/elfldr) payload with the
[ps5-payload-dev SDK](https://github.com/ps5-payload-dev/sdk). Profiling
sessions are driven, and their data returned, over TCP (default port **9077**).

```
$ host/ps5perf.py -H 192.168.0.190 record -p eboot.bin -g -F 499 -d 10 -o game
[ps5perf] 769 samples captured into game.ps5perf
[ps5perf] wrote game.perf-script, game.folded, game.svg
# Samples: 769  of event 'cpu-clock'  (sampling mode: precise, 499 Hz)
# Overhead  Samples  Command    Shared Object            Symbol
    36.15%      278  eboot.bin  libkernel.sprx           [.] clock_gettime
    16.78%      129  eboot.bin  libkernel.sprx           [.] _nanosleep
     6.63%       51  eboot.bin  eboot.bin                [.] sub_160de0
```

## Why not a straight port of `tools/perf`?

Linux perf is a front-end for the Linux-only `perf_event_open(2)` syscall
and the kernel's PMU/ring-buffer machinery. The PS5 runs a FreeBSD 11 derived
kernel that has neither (and no `hwpmc` either), so `perf.c` cannot work there
unchanged. ps5-perf keeps perf's user-facing model (the same sub-commands, the
`cpu-clock` event, `perf stat`/`perf report` style output and the `perf script`
interchange format) and re-implements the event sources with what the PS5
offers to a payload with kernel r/w:

| perf concept            | ps5-perf implementation |
|-------------------------|-------------------------|
| `cpu-clock` sampling    | timer-driven: read the target's thread states from kernel `struct thread`; if any thread is on a CPU, `SIGSTOP` the ptrace-attached target, read registers of the running threads, `PT_CONTINUE` |
| call graphs (`-g`)      | frame-pointer (`rbp`) unwinding through `PT_IO`, plus leaf-caller recovery for frameless functions (syscall stubs) |
| software counters (`stat`) | process `kinfo_proc` rusage + per-thread `td_ru`/`td_runtime` |
| symbols / DSOs          | kernel dynlib object list (module map + dynsym), `.eh_frame_hdr` function boundaries for stripped code, Sony NIDs resolved to names |
| hardware events         | not available (no PMU access from user space) |

Firmware-specific `struct thread` offsets are not hard-coded: at start-up a
calibration thread with a known tid, name, CPU time and rusage is matched
against its own kernel `struct thread`. On fw 12.20 this yields
`plist@0x10 tid@0x9c name@0x294 runtime@0x238 ru@0x168 state@0x400`.

## Building

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make                       # -> ps5-perf.elf
make PS5PERF_PORT=9100     # other listening port
```

The build generates `build/nid_table.c` (NID -> name, ~8600 symbols) from the
SDK's stub libraries so that the console-side `report`/`top`/`script` output
already shows `clock_gettime` instead of `lLMT9vJAck0`.

## Running

```sh
make deploy PS5_HOST=192.168.0.190          # sends ps5-perf.elf to elfldr :9021
```

A notification "ps5-perf 1.0.0 listening on port 9077" appears, and klog shows
the calibration result. The payload stays resident; `shutdown` stops it (any
running session first detaches cleanly from its target).

## Protocol

Plain text, one command per line, e.g. `nc 192.168.0.190 9077`. Each
command's output ends with a line `#END rc=<n>`. Sending any input while a
command runs stops it (the target is always detached and resumed, also if the
client disconnects or the payload is shut down).

| command | |
|---|---|
| `ps` | processes: pid, state, threads, CPU time, RSS, title id |
| `threads -p <pid\|name>` | per-thread state, CPU time, context switches, faults |
| `maps -p <pid\|name>` | loaded modules, function/export counts |
| `list` | available events |
| `stat -p X [-d s] [-I ms] [--per-thread] [-t tid]` | `perf stat` style counters |
| `report -p X [-F hz] [-g] [-d s] [-s comm,tid,dso,sym] [--children] [-n N]` | sample, then print a `perf report --stdio` style profile |
| `top -p X [-F hz] [-I ms] [-n N]` | live profile, a frame every `-I` ms |
| `script -p X [-F hz] [-g] [-d s]` | stream samples in `perf script` text format |
| `record -p X [-F hz] [-g] [-d s] [--no-syms]` | stream raw samples for the host tool |
| `version`, `help`, `quit`, `shutdown` | |

Common options: `-p` accepts a pid or a process name (`eboot.bin`,
`SceShellUI`, `payload.elf`, ...), `-F` frequency (default 99 Hz, max 2000),
`-d` duration (also `-- sleep N`), `-t` single thread, `--max-stack N`,
an optional leading `perf` is ignored (`perf top -p eboot.bin` works).

### Sampling modes

* **precise** (default): only threads that are on a CPU at the sampling
  instant are sampled, each with a weight of one period - the statistical
  model of perf's `cpu-clock`. When nothing in the target runs, it is not
  stopped at all.
* `--weighted`: every thread that consumed CPU since the last tick is sampled,
  weighted by its run-time delta. More samples per stop, but a thread that ran
  and then blocked is attributed to where it blocked.
* `--off-cpu`: every thread on every tick (wall-clock profile, shows where
  threads wait).

Overhead: the target is paused for ~15-40 us per stop (~0.03-1.3% of wall
time at 99-499 Hz in tests, up to a few ms worst case for processes with
hundreds of threads). Accuracy on the synthetic test target
(`tests/burner`): function split 79.9% / 20.1% measured vs. 81.8% / 18.2%
expected; per-thread CPU within ~10% of the kernel's own accounting.

## Host tool

`host/ps5perf.py` (Python 3, no dependencies; uses `llvm-nm` for symbols):

```sh
H="-H 192.168.0.190"
host/ps5perf.py $H ps
host/ps5perf.py $H stat -p eboot.bin -d 5 --per-thread
host/ps5perf.py $H top -p eboot.bin                       # live, Ctrl-C to stop
host/ps5perf.py $H record -p eboot.bin -g -F 499 -o game  # Ctrl-C to stop
host/ps5perf.py report -i game.ps5perf -g --children      # offline re-analysis
host/ps5perf.py script -i game.ps5perf > game.txt
```

`record` writes:

* `game.ps5perf` - raw recording (replayable with `-i`)
* `game.perf-script` - `perf script` text: load it into
  [speedscope](https://www.speedscope.app), the
  [Firefox Profiler](https://profiler.firefox.com) or Brendan Gregg's
  `stackcollapse-perf.pl | flamegraph.pl`
* `game.folded` - collapsed stacks for `flamegraph.pl` / inferno
* `game.svg` - a self-contained interactive flame graph

Symbolization:

* Sony system modules: exported NIDs are resolved to names computed from the
  SDK stub libraries (`--nid-names FILE` adds more names);
* stripped code (e.g. a retail `eboot.bin`): functions are recovered from
  `.eh_frame_hdr` and named `sub_<offset>` (IDA style);
* your own code: `--sym MODULE=ELF` or `--symfs DIR` with unstripped ELFs.
  Payloads loaded by elfldr appear as module `payload.elf`, e.g.
  `--sym payload.elf=build/my_payload.elf`.

## Layout

```
src/main.c        TCP server, perf.c-style command table
src/sampler.c     cpu-clock sampling engine (ptrace stop/inspect/continue, unwinding)
src/kthread.c     struct thread discovery/calibration and per-thread accounting
src/modules.c     module map, dynsym, .eh_frame_hdr, anonymous exec regions
src/proc.c        sysctl process info, ptrace wrappers
src/cmd_*.c       ps/threads/maps/list/stat/record/script/report/top
tools/gen_nids.py build-time NID table generator
host/ps5perf.py   host client and converters
tests/burner      synthetic target with a known CPU profile
```

## Limitations

* No hardware events (cycles, cache misses, ...): no PMU access.
* One sampling session at a time (`stat`/`ps`/`threads`/`maps` run concurrently).
* Frame-pointer unwinding: code built without frame pointers yields short stacks.
* Only one tracer can attach to a process: stop other debuggers (e.g. gdb,
  ps5debug attached to the same process) before sampling it.
* The `struct proc` dynlib list offset (`0x3e8`) and the `kinfo_proc` layout
  quirk are taken from / verified on fw 12.20 with SDK v0.45.

## License

GPL-3.0-or-later, like the ps5-payload-dev SDK and elfldr it builds on. See
[LICENSE](LICENSE).
