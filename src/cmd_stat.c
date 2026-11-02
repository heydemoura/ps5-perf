/* perf stat: software counters derived from per-thread kernel accounting. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ps5perf.h"

typedef struct counters {
  double   task_clock_ms;
  uint64_t cs, ics, minflt, majflt, inblock, oublock;
} counters_t;

static void
delta_counters(const thread_info_t *a, int na, const thread_info_t *b, int nb,
               counters_t *c, pid_t only_tid) {
  memset(c, 0, sizeof *c);
  for(int i = 0; i < nb; i++) {
    const thread_info_t *t = &b[i], *p = NULL;
    if(only_tid > 0 && t->tid != only_tid) continue;
    for(int j = 0; j < na; j++) if(a[j].tid == t->tid) { p = &a[j]; break; }
    thread_info_t z;
    if(!p) { memset(&z, 0, sizeof z); p = &z; }   /* thread born during run */
#define D(f) (t->f > p->f ? t->f - p->f : 0)
    c->task_clock_ms += D(runtime_us) / 1e3;
    c->cs     += D(nvcsw);
    c->ics    += D(nivcsw);
    c->minflt += D(minflt);
    c->majflt += D(majflt);
    c->inblock += D(inblock);
    c->oublock += D(oublock);
#undef D
  }
}

static void
fmt_count(char *buf, size_t len, uint64_t v) {
  char tmp[32];
  int n = snprintf(tmp, sizeof tmp, "%lu", (unsigned long)v), w = 0;
  for(int i = 0; i < n && w < (int)len - 1; i++) {
    buf[w++] = tmp[i];
    if((n - i - 1) % 3 == 0 && i != n - 1 && w < (int)len - 1) buf[w++] = ',';
  }
  buf[w] = 0;
}

static void
rate(char *buf, size_t len, double v, double secs) {
  double r = secs > 0 ? v / secs : 0;
  if(r >= 1e6) snprintf(buf, len, "%8.3f M/sec", r / 1e6);
  else if(r >= 1e3) snprintf(buf, len, "%8.3f K/sec", r / 1e3);
  else snprintf(buf, len, "%8.3f /sec", r);
}

static void
print_full(out_t *o, const counters_t *c, double secs) {
  char n[32], r[32];

  out_printf(o, "%18.2f msec %-28s #  %8.3f CPUs utilized\n", c->task_clock_ms, "task-clock",
             secs > 0 ? c->task_clock_ms / 1e3 / secs : 0);
  fmt_count(n, sizeof n, c->cs + c->ics); rate(r, sizeof r, c->cs + c->ics, secs);
  out_printf(o, "%18s      %-28s #  %s\n", n, "context-switches", r);
  fmt_count(n, sizeof n, c->ics); rate(r, sizeof r, c->ics, secs);
  out_printf(o, "%18s      %-28s #  %s\n", n, "involuntary-context-switches", r);
  out_printf(o, "%18s      %-28s\n", "<not supported>", "cpu-migrations");
  fmt_count(n, sizeof n, c->minflt + c->majflt); rate(r, sizeof r, c->minflt + c->majflt, secs);
  out_printf(o, "%18s      %-28s #  %s\n", n, "page-faults", r);
  fmt_count(n, sizeof n, c->majflt);
  out_printf(o, "%18s      %-28s\n", n, "major-faults");
  fmt_count(n, sizeof n, c->inblock);
  out_printf(o, "%18s      %-28s\n", n, "block-input");
  fmt_count(n, sizeof n, c->oublock);
  out_printf(o, "%18s      %-28s\n", n, "block-output");
  out_printf(o, "%18s      %-28s\n", "<not supported>", "cycles");
  out_printf(o, "%18s      %-28s\n", "<not supported>", "instructions");
}

static void
delta_total(const thread_info_t *a, const thread_info_t *b, counters_t *c) {
  thread_info_t x = *a, y = *b;
  x.tid = y.tid = 1;
  delta_counters(&x, 1, &y, 1, c, -1);
}

int
cmd_stat(int argc, char **argv, out_t *o) {
  opts_t op;
  char comm[64] = "";
  thread_info_t tot0, toti, tot1;
  thread_info_t *t0 = calloc(MAX_THREADS, sizeof *t0);
  thread_info_t *t1 = calloc(MAX_THREADS, sizeof *t1);
  int n0 = -1, n1 = -1, rc = -1, exited = 0;

  if(!t0 || !t1) goto out;
  if(opts_parse(argc, argv, &op, o) || resolve_target(&op, o)) goto out;
  if(proc_totals(op.pid, &tot0, comm, sizeof comm)) {
    out_printf(o, "error: unable to read process %d\n", op.pid);
    goto out;
  }
  if(op.per_thread || op.tid > 0) {
    if((n0 = proc_threads(op.pid, t0, MAX_THREADS, NULL, 0)) < 0)
      out_printf(o, "# per-thread counters unavailable: %s\n", kthreads_status());
  }
  toti = tot0;

  if(op.duration <= 0)
    out_printf(o, "# counting process %d (%s), send a newline to stop\n", op.pid, comm);
  if(op.interval_ms > 0)
    out_printf(o, "#%14s %18s      %-28s\n", "time", "counts", "event");
  out_flush(o);

  uint64_t start = now_ns(), last = start;
  for(;;) {
    sleep_ns(10 * 1000000ull);
    uint64_t now = now_ns();
    double el = (now - start) / 1e9;
    int stop = (op.duration > 0 && el >= op.duration) || client_wants_stop(o->fd);

    if(op.interval_ms > 0 && (now - last) >= (uint64_t)op.interval_ms * 1000000ull) {
      thread_info_t cur;
      counters_t c;
      if(proc_totals(op.pid, &cur, NULL, 0)) { exited = 1; break; }
      delta_total(&toti, &cur, &c);
      double secs = (now - last) / 1e9;
      char a[32], b[32];
      out_printf(o, "%15.9f %18.2f msec %-28s #  %6.3f CPUs utilized\n", el, c.task_clock_ms,
                 "task-clock", c.task_clock_ms / 1e3 / secs);
      fmt_count(a, sizeof a, c.cs + c.ics);
      out_printf(o, "%15.9f %18s      %-28s\n", el, a, "context-switches");
      fmt_count(b, sizeof b, c.minflt + c.majflt);
      out_printf(o, "%15.9f %18s      %-28s\n", el, b, "page-faults");
      out_flush(o);
      toti = cur;
      last = now;
    } else if(!proc_exists(op.pid)) {
      exited = 1;
      break;
    }
    if(stop || o->err) break;
  }

  double secs = (now_ns() - start) / 1e9;
  if(exited || proc_totals(op.pid, &tot1, NULL, 0)) { tot1 = toti; exited = 1; }
  if(n0 >= 0 && !exited) n1 = proc_threads(op.pid, t1, MAX_THREADS, NULL, 0);

  counters_t c;
  if(op.tid > 0 && n0 >= 0 && n1 >= 0) delta_counters(t0, n0, t1, n1, &c, op.tid);
  else delta_total(&tot0, &tot1, &c);

  out_printf(o, "\n Performance counter stats for process id '%d' (%s)%s%s:\n\n", op.pid, comm,
             op.tid > 0 ? ", thread" : "", exited ? " [process exited]" : "");
  print_full(o, &c, secs);

  if(op.per_thread && n1 >= 0) {
    out_printf(o, "\n %-24s %8s %14s %10s %10s %10s\n", "thread", "tid", "task-clock(ms)",
               "CPUs", "ctx-sw", "faults");
    for(int i = 0; i < n1; i++) {
      counters_t tc;
      if(op.tid > 0 && t1[i].tid != op.tid) continue;
      delta_counters(t0, n0, &t1[i], 1, &tc, -1);
      if(!tc.task_clock_ms && !tc.cs && !tc.ics) continue;
      out_printf(o, " %-24s %8d %14.2f %10.3f %10lu %10lu\n", t1[i].name, t1[i].tid,
                 tc.task_clock_ms, tc.task_clock_ms / 1e3 / secs,
                 (unsigned long)(tc.cs + tc.ics), (unsigned long)(tc.minflt + tc.majflt));
    }
  }
  out_printf(o, "\n %18.9f seconds time elapsed\n\n", secs);
  rc = 0;

out:
  free(t0);
  free(t1);
  return rc;
}
