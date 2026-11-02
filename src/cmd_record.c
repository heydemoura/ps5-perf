/* perf record / perf script.
 *
 * `record` streams a compact line based format that the host tool turns into
 * perf-script text, folded stacks, flame graphs and reports:
 *
 *   #ps5-perf-record v1
 *   H pid=<pid> comm=<comm> freq=<hz> callgraph=<0|1> off_cpu=<0|1> fw=<hex>
 *   M <idx> <base> <text_end> <map_end> <name> <path>      (hex addresses)
 *   F <idx> <start> <size> <name|->                         (lazily, before use)
 *   T <tid> <thread name>
 *   S <time_ns> <tid> <cpu> <weight_ns> <ip>[,<ip>...]      (hex ips)
 *   X <key=value ...>                                       (trailer)
 *
 * `script` symbolizes on the console and prints the classic `perf script`
 * layout, which FlameGraph's stackcollapse-perf.pl, speedscope and the
 * Firefox profiler can import directly. */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ps5/kernel.h>

#include "ps5perf.h"

pthread_mutex_t g_sampler_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct rec_ctx {
  out_t     *o;
  modlist_t *ml;
  uint8_t  **sent;     /* per module bitmap of functions already emitted */
  int        script;
  pid_t      pid;
} rec_ctx_t;

static void
rec_thread(void *vctx, pid_t tid, const char *name) {
  rec_ctx_t *c = vctx;
  if(!c->script) out_printf(c->o, "T %d %s\n", tid, name);
}

static void
emit_func(rec_ctx_t *c, uint64_t addr) {
  const module_t *m = module_find(c->ml, addr);
  if(!m) return;
  const func_t *f = func_find(m, addr);
  if(!f) return;
  int mi = (int)(m - c->ml->mods);
  int fi = (int)(f - m->funcs);
  if(!c->sent[mi]) return;
  if(c->sent[mi][fi >> 3] & (1 << (fi & 7))) return;
  c->sent[mi][fi >> 3] |= 1 << (fi & 7);
  out_printf(c->o, "F %d %lx %x %s\n", mi, (unsigned long)f->start, f->size,
             f->name >= 0 ? m->strpool + f->name : "-");
}

static void
rec_sample(void *vctx, const sample_t *s) {
  rec_ctx_t *c = vctx;

  if(!c->script) {
    if(c->sent) {
      for(int i = 0; i < s->nips; i++) emit_func(c, i ? s->ips[i] - 1 : s->ips[i]);
    }
    char line[MAX_STACK * 17 + 128];
    int n = snprintf(line, sizeof line, "S %lu %d %d %lu ", (unsigned long)s->time_ns, s->tid,
                     s->cpu, (unsigned long)s->weight_ns);
    for(int i = 0; i < s->nips && n < (int)sizeof(line) - 20; i++)
      n += snprintf(line + n, sizeof(line) - n, i ? ",%lx" : "%lx", (unsigned long)s->ips[i]);
    line[n++] = '\n';
    out_write(c->o, line, n);
    return;
  }

  /* perf script format */
  out_printf(c->o, "%s %d/%d [%03d] %lu.%06lu: %lu cpu-clock:\n", s->tname, c->pid, s->tid,
             s->cpu, (unsigned long)(s->time_ns / 1000000000ull),
             (unsigned long)((s->time_ns / 1000) % 1000000), (unsigned long)s->weight_ns);
  for(int i = 0; i < s->nips; i++) {
    char sym[160];
    const char *dso;
    uint64_t off;
    /* return addresses point after the call; look up the call itself */
    uint64_t look = i ? s->ips[i] - 1 : s->ips[i];
    symbolize(c->ml, look, sym, sizeof sym, &dso, &off);
    if(i) off += 1;
    if(off) out_printf(c->o, "\t%16lx %s+0x%lx (%s)\n", (unsigned long)s->ips[i], sym,
                       (unsigned long)off, dso);
    else out_printf(c->o, "\t%16lx %s (%s)\n", (unsigned long)s->ips[i], sym, dso);
  }
  out_write(c->o, "\n", 1);
}

static int
rec_tick(void *vctx, double t) {
  rec_ctx_t *c = vctx;
  (void)t;
  out_flush(c->o);
  return c->o->err != 0;
}

static int
do_record(int argc, char **argv, out_t *o, int script) {
  opts_t op;
  modlist_t ml;
  rec_ctx_t ctx;
  sampler_cfg_t cfg;
  sampler_stats_t st;
  char comm[64] = "";
  char err[256] = "";
  thread_info_t ti;
  int rc;

  if(opts_parse(argc, argv, &op, o) || resolve_target(&op, o)) return -1;
  if(pthread_mutex_trylock(&g_sampler_lock)) {
    out_printf(o, "error: another sampling session is active\n");
    return -1;
  }
  proc_threads(op.pid, &ti, 1, comm, sizeof comm);

  memset(&ml, 0, sizeof ml);
  modules_load(op.pid, &ml, script || !op.no_syms, 0);

  memset(&ctx, 0, sizeof ctx);
  ctx.o = o;
  ctx.ml = &ml;
  ctx.script = script;
  ctx.pid = op.pid;
  if(!script && !op.no_syms && ml.n) {
    ctx.sent = calloc(ml.n, sizeof(uint8_t *));
    for(int i = 0; ctx.sent && i < ml.n; i++)
      ctx.sent[i] = calloc((ml.mods[i].nfuncs + 7) / 8 + 1, 1);
  }

  uint32_t fw = kernel_get_fw_version();
  if(!script) {
    out_printf(o, "#ps5-perf-record v1\n");
    out_printf(o, "H pid=%d comm=%s freq=%d callgraph=%d off_cpu=%d fw=%x\n", op.pid, comm,
               op.freq, op.callgraph, op.off_cpu, fw);
    for(int i = 0; i < ml.n; i++) {
      module_t *m = &ml.mods[i];
      out_printf(o, "M %d %lx %lx %lx %s %s\n", i, (unsigned long)m->base,
                 (unsigned long)m->text_end, (unsigned long)m->map_end, m->name,
                 m->path[0] ? m->path : "-");
    }
  } else {
    out_printf(o, "# ps5-perf script: pid %d (%s), cpu-clock @ %d Hz%s, %d modules\n", op.pid,
               comm, op.freq, op.callgraph ? ", call graph (fp)" : "", ml.n);
    if(op.duration <= 0) out_printf(o, "# send a newline to stop\n");
  }
  out_flush(o);

  memset(&cfg, 0, sizeof cfg);
  cfg.pid = op.pid;
  cfg.tid = op.tid;
  cfg.freq = op.freq;
  cfg.duration = op.duration;
  cfg.callgraph = op.callgraph;
  cfg.max_stack = op.max_stack;
  cfg.off_cpu = op.off_cpu;
  cfg.weighted = op.weighted;
  cfg.client_fd = o->fd;
  cfg.mods = &ml;
  cfg.on_sample = rec_sample;
  cfg.on_thread = rec_thread;
  cfg.on_tick = rec_tick;
  cfg.ctx = &ctx;

  o->hold = 1;          /* samples are emitted while the target is stopped */
  rc = sampler_run(&cfg, &st, err, sizeof err);
  o->hold = 0;
  if(rc) {
    out_printf(o, "%serror: %s\n", script ? "# " : "", err);
  } else {
    uint64_t nstops = st.rounds - st.no_stop_rounds;
    double avg_us = nstops ? st.stop_ns_total / 1e3 / nstops : 0;
    if(!script)
      out_printf(o, "X rounds=%lu samples=%lu idle_skipped=%lu no_stop_rounds=%lu elapsed=%.6f "
                 "stop_avg_us=%.1f stop_max_us=%.1f exited=%d mode=%s\n", (unsigned long)st.rounds,
                 (unsigned long)st.samples, (unsigned long)st.idle_skipped,
                 (unsigned long)st.no_stop_rounds, st.elapsed, avg_us,
                 st.stop_ns_max / 1e3, st.exited, sampler_mode_short(st.mode));
    else
      out_printf(o, "# %lu samples (%s) in %lu rounds over %.3fs, target stopped avg %.1fus "
                 "max %.1fus per stop%s\n", (unsigned long)st.samples, sampler_mode_name(st.mode),
                 (unsigned long)st.rounds, st.elapsed, avg_us, st.stop_ns_max / 1e3,
                 st.exited ? ", target exited" : "");
  }

  if(ctx.sent) {
    for(int i = 0; i < ml.n; i++) free(ctx.sent[i]);
    free(ctx.sent);
  }
  modules_free(&ml);
  pthread_mutex_unlock(&g_sampler_lock);
  return rc;
}

int
cmd_record(int argc, char **argv, out_t *o) {
  return do_record(argc, argv, o, 0);
}

int
cmd_script(int argc, char **argv, out_t *o) {
  return do_record(argc, argv, o, 1);
}
