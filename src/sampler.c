/* cpu-clock sampling engine.
 *
 * Linux perf programs a timer/PMU event per CPU and lets the kernel write
 * samples into a ring buffer. The PS5 kernel has no perf_event_open(2), so we
 * emulate a cpu-clock event from user space:
 *
 *   every 1/F seconds:  SIGSTOP the (ptrace-attached) target, wait for it,
 *                       read the per-thread on-CPU runtime from the kernel,
 *                       and for every thread that consumed CPU since the
 *                       previous tick read its registers and walk the frame
 *                       pointer chain; then PT_CONTINUE it.
 *
 * Each sample is weighted with the thread's runtime delta (ns), i.e. the
 * "period" of a perf cpu-clock sample, so threads that ran more weigh more
 * and threads that slept are skipped (unless --off-cpu is requested). */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>

#include <ps5/kernel.h>

#include "ps5perf.h"

volatile pid_t g_attached_pid = 0;

/* Called from fatal signal handlers: never leave a target stopped/traced. */
void
sampler_emergency_detach(void) {
  pid_t pid = g_attached_pid;
  int status;

  if(pid <= 0) return;
  g_attached_pid = 0;
  kill(pid, SIGSTOP);
  for(int i = 0; i < 64; i++) {
    if(waitpid(pid, &status, 0) != pid) break;
    if(!WIFSTOPPED(status)) return;
    if(WSTOPSIG(status) == SIGSTOP) break;
    pt_call(PT_CONTINUE, pid, (void *)1, WSTOPSIG(status));
  }
  pt_detach(pid);
}

/* --------------------------------------------------- page cache ------- */

#define PC_SLOTS 128
#define PAGE_SZ  4096ull

typedef struct pcache {
  pid_t    pid;
  uint32_t gen;
  struct { uint64_t page; uint32_t gen; int ok; uint8_t data[PAGE_SZ]; } slot[PC_SLOTS];
} pcache_t;

static int
pc_read64(pcache_t *pc, uint64_t addr, uint64_t *val) {
  uint64_t page = addr & ~(PAGE_SZ - 1);
  unsigned idx = (unsigned)((page >> 12) * 2654435761u) % PC_SLOTS;

  if(addr & 7) return -1;
  if(pc->slot[idx].gen != pc->gen || pc->slot[idx].page != page) {
    pc->slot[idx].gen = pc->gen;
    pc->slot[idx].page = page;
    pc->slot[idx].ok = !pt_read(pc->pid, page, pc->slot[idx].data, PAGE_SZ);
  }
  if(!pc->slot[idx].ok) return -1;
  *val = *(uint64_t *)(pc->slot[idx].data + (addr - page));
  return 0;
}

/* ------------------------------------------------- leaf handling ------ */

/* Code is mapped execute-only on the PS5, so ptrace cannot read it, but the
 * kernel copy helpers can. Results are cached per address. */
#define CC_SLOTS 4096
static struct { uint64_t addr; uint8_t ok, bytes[8]; } g_code[CC_SLOTS];

static const uint8_t *
code_at(pid_t pid, uint64_t addr) {
  unsigned i = (unsigned)((addr * 0x9E3779B97F4A7C15ull) >> 52) % CC_SLOTS;
  if(g_code[i].addr != addr || !g_code[i].ok) {
    g_code[i].addr = addr;
    g_code[i].ok = kernel_proc_copyout(pid, (intptr_t)addr, g_code[i].bytes, 8) >= 0;
  }
  return g_code[i].ok ? g_code[i].bytes : NULL;
}

/* does `ret` look like a return address, i.e. is it preceded by a call? */
static int
is_return_address(pid_t pid, const sampler_cfg_t *cfg, uint64_t ret) {
  const module_t *m;
  if(ret < 0x1000 || !cfg->mods || !(m = module_find(cfg->mods, ret)) || ret >= m->text_end)
    return 0;
  const uint8_t *b = code_at(pid, ret - 8);
  if(!b) return 0;
  /* b[0..7] = bytes ret-8 .. ret-1 */
  if(b[3] == 0xe8) return 1;                                   /* call rel32 */
  if(b[6] == 0xff && ((b[7] >> 3) & 7) == 2) return 1;         /* call *%reg */
  if(b[5] == 0xff && ((b[6] >> 3) & 7) == 2) return 1;         /* call *(%reg),disp8/sib */
  if(b[2] == 0xff && ((b[3] >> 3) & 7) == 2) return 1;         /* call *disp32(...) */
  if(b[1] == 0xff && ((b[2] >> 3) & 7) == 2) return 1;         /* call *disp32(sib) */
  return 0;
}

/* For a sample taken in a function that has not (yet) set up a frame
 * pointer - typically a libkernel syscall stub - the rbp chain skips the
 * immediate caller. Recover it from the stack top when it is safe to. */
static uint64_t
leaf_caller(pid_t pid, pcache_t *pc, const sampler_cfg_t *cfg, const struct reg *r) {
  const module_t *m = cfg->mods ? module_find(cfg->mods, r->r_rip) : NULL;
  const func_t *f = m ? func_find(m, r->r_rip) : NULL;
  uint64_t ret = 0;

  if(f) {
    uint64_t start = m->base + f->start;
    const uint8_t *p = code_at(pid, start);
    int framed = p && p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89 && p[3] == 0xe5;
    if(framed && (uint64_t)r->r_rip == start) pc_read64(pc, r->r_rsp, &ret);
    else if(framed && (uint64_t)r->r_rip == start + 1) pc_read64(pc, r->r_rsp + 8, &ret);
    else if(!framed) pc_read64(pc, r->r_rsp, &ret);
    else return 0;
  } else {
    pc_read64(pc, r->r_rsp, &ret);
  }
  return is_return_address(pid, cfg, ret) ? ret : 0;
}

static int
unwind(pcache_t *pc, const sampler_cfg_t *cfg, const struct reg *r, uint64_t *ips, int max) {
  int n = 0;
  uint64_t fp = r->r_rbp, sp = r->r_rsp;

  ips[n++] = r->r_rip;
  if(!cfg->callgraph) return n;

  uint64_t lc = leaf_caller(pc->pid, pc, cfg, r);
  uint64_t first = 0;
  if(lc && !(fp >= sp && !pc_read64(pc, fp + 8, &first) && first == lc) && n < max)
    ips[n++] = lc;

  while(n < max) {
    uint64_t next, ret;
    if(fp < sp || fp - sp > (64ull << 20) || (fp & 7)) break;
    if(pc_read64(pc, fp, &next) || pc_read64(pc, fp + 8, &ret)) break;
    if(ret < 0x1000) break;
    if(cfg->mods && cfg->mods->n && !module_find(cfg->mods, ret)) break;
    ips[n++] = ret;
    if(next <= fp) break;
    sp = fp + 16;
    fp = next;
  }
  return n;
}

/* --------------------------------------------------- thread table ----- */

typedef struct ttab {
  thread_info_t t[MAX_THREADS];
  int n;
} ttab_t;

static const thread_info_t *
ttab_find(const ttab_t *tt, pid_t tid) {
  for(int i = 0; i < tt->n; i++)
    if(tt->t[i].tid == tid) return &tt->t[i];
  return NULL;
}

/* Thread list of the stopped target. Normally from kernel struct thread
 * (with run times); if that is unavailable fall back to ptrace's LWP list,
 * in which case every thread is treated as running (wall-clock profile). */
static int
get_threads(pid_t pid, ttab_t *tt, int *approx) {
  lwpid_t lwps[MAX_THREADS];
  int n;

  *approx = 0;
  tt->n = proc_threads(pid, tt->t, MAX_THREADS, NULL, 0);
  if(tt->n > 0) return 0;

  *approx = 1;
  n = pt_call(PT_GETLWPLIST, pid, lwps, MAX_THREADS);
  if(n < 0) { tt->n = 0; return -1; }
  for(int i = 0; i < n; i++) {
    struct ptrace_lwpinfo li;
    memset(&tt->t[i], 0, sizeof tt->t[i]);
    tt->t[i].tid = lwps[i];
    memset(&li, 0, sizeof li);
    if(!pt_call(PT_LWPINFO, lwps[i], &li, sizeof li))
      snprintf(tt->t[i].name, sizeof tt->t[i].name, "%s", li.pl_tdname);
    tt->t[i].lastcpu = -1;
  }
  tt->n = n;
  return 0;
}

/* ---------------------------------------------------- stop/cont ------- */

/* Wait until the target reports our SIGSTOP. Other signals that arrive in
 * the meantime are re-injected so the target behaves as if untraced. */
static int
wait_stopped(pid_t pid, int *exited) {
  int status;

  for(int tries = 0; tries < 256; tries++) {
    pid_t r = waitpid(pid, &status, 0);
    if(r < 0) {
      if(errno == EINTR) continue;
      return -1;
    }
    if(WIFEXITED(status) || WIFSIGNALED(status)) {
      *exited = 1;
      return -1;
    }
    if(!WIFSTOPPED(status)) continue;
    if(WSTOPSIG(status) == SIGSTOP) return 0;
    if(pt_call(PT_CONTINUE, pid, (void *)1, WSTOPSIG(status)) < 0) return -1;
  }
  return -1;
}

/* Sleep until `deadline`, promptly forwarding any signal the target receives
 * while running (a traced process stops on every signal until the tracer
 * lets it continue). */
static int
sleep_forwarding(pid_t pid, uint64_t deadline, int *exited) {
  for(;;) {
    int status;
    pid_t r = waitpid(pid, &status, WNOHANG);
    if(r == pid) {
      if(WIFEXITED(status) || WIFSIGNALED(status)) {
        *exited = 1;
        return -1;
      }
      if(WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        pt_call(PT_CONTINUE, pid, (void *)1, sig == SIGSTOP ? 0 : sig);
      }
    }
    uint64_t now = now_ns();
    if(now >= deadline) return 0;
    uint64_t left = deadline - now;
    sleep_ns(left > 2000000 ? 2000000 : left);
  }
}

/* ---------------------------------------------------------- main ------ */

enum { MODE_PRECISE, MODE_WEIGHTED, MODE_OFFCPU, MODE_LWP };
#define WEIGHTED_MIN_US 50

const char *
sampler_mode_name(int mode) {
  static const char *n[] = { "precise on-cpu", "weighted by run time", "off-cpu/wall-clock",
                             "lwp fallback/wall-clock" };
  return mode >= 0 && mode < 4 ? n[mode] : "?";
}

const char *
sampler_mode_short(int mode) {
  static const char *n[] = { "precise", "weighted", "off-cpu", "lwp-fallback" };
  return mode >= 0 && mode < 4 ? n[mode] : "?";
}

/* Detach safely: the target must be stopped for PT_DETACH. */
static void
detach(pid_t pid, int *exited) {
  if(*exited) return;
  if(!kill(pid, SIGSTOP) && !wait_stopped(pid, exited)) pt_detach(pid);
  else if(!*exited) pt_detach(pid);
}

static void
emit(sampler_cfg_t *cfg, sampler_stats_t *st, pcache_t *pc, sample_t *s,
     const thread_info_t *t, uint64_t ts, uint64_t weight_ns) {
  struct reg r;

  if(pt_call(PT_GETREGS, t->tid, &r, 0) < 0) return;   /* thread exited */
  s->time_ns = ts;
  s->tid = t->tid;
  s->tname = t->name;
  s->weight_ns = weight_ns;
  s->on_cpu = t->stat == TD_RUNNING;
  s->cpu = t->oncpu < 0 ? 0 : t->oncpu;
  s->nips = unwind(pc, cfg, &r, s->ips, cfg->max_stack);
  st->samples++;
  if(cfg->on_sample) cfg->on_sample(cfg->ctx, s);
}

/*
 * Modes:
 *  precise  (default) at every tick, read the target's thread states from
 *           the kernel *before* stopping it; only threads that are on a CPU
 *           at that instant are sampled, each with weight = one period. This
 *           is the statistical model of perf's cpu-clock event. If nothing
 *           runs, the target is not even stopped.
 *  weighted (--weighted) every thread that consumed CPU since the previous
 *           tick is sampled, weighted by its run-time delta. More samples per
 *           stop, but a thread that ran and then blocked is attributed to its
 *           blocking point.
 *  off-cpu  (--off-cpu) every thread, weight = one period (wall clock).
 *  lwp      fallback when struct thread could not be calibrated: ptrace's
 *           LWP list, every thread sampled (wall clock).
 */
int
sampler_run(sampler_cfg_t *cfg, sampler_stats_t *st, char *err, size_t errlen) {
  ttab_t *prev = calloc(1, sizeof(ttab_t));
  ttab_t *cur = calloc(1, sizeof(ttab_t));
  pcache_t *pc = calloc(1, sizeof(pcache_t));
  sample_t *s = calloc(1, sizeof(sample_t));
  pid_t pid = cfg->pid;
  int rc = -1, exited = 0, approx = 0, mode;
  uint64_t period = 1000000000ull / (uint64_t)cfg->freq;

  memset(st, 0, sizeof *st);
  if(!prev || !cur || !pc || !s) {
    snprintf(err, errlen, "out of memory");
    goto out_free;
  }
  pc->pid = pid;

  kthreads_init();
  if(cfg->off_cpu) mode = MODE_OFFCPU;
  else if(cfg->weighted) mode = MODE_WEIGHTED;
  else mode = kthreads_have_state() ? MODE_PRECISE : MODE_WEIGHTED;

  if(pt_attach(pid)) {
    snprintf(err, errlen, "ptrace attach to %d failed: %s", pid, strerror(errno));
    goto out_free;
  }
  g_attached_pid = pid;

  get_threads(pid, prev, &approx);
  if(approx) mode = MODE_LWP;
  st->mode = mode;
  for(int i = 0; i < prev->n; i++)
    if(cfg->on_thread) cfg->on_thread(cfg->ctx, prev->t[i].tid, prev->t[i].name);

  uint64_t t0 = now_ns();
  uint64_t next = t0 + period;

  if(pt_call(PT_CONTINUE, pid, (void *)1, 0) < 0) {
    snprintf(err, errlen, "PT_CONTINUE failed: %s", strerror(errno));
    pt_detach(pid);
    g_attached_pid = 0;
    goto out_free;
  }

  for(;;) {
    if(sleep_forwarding(pid, next, &exited)) break;
    uint64_t tnow = now_ns();
    if(cfg->duration > 0 && (tnow - t0) / 1e9 >= cfg->duration) break;
    if(g_shutdown || client_wants_stop(cfg->client_fd)) break;

    int nsel = 0;
    if(mode != MODE_LWP) {
      /* thread states + run times, read while the target keeps running */
      if(get_threads(pid, cur, &approx) || approx) {
        if(!proc_exists(pid)) { exited = 1; break; }
        goto next_tick;
      }
      for(int i = 0; i < cur->n; i++) {
        thread_info_t *t = &cur->t[i];
        const thread_info_t *p = ttab_find(prev, t->tid);
        uint64_t delta = p ? (t->runtime_us > p->runtime_us ? t->runtime_us - p->runtime_us : 0)
                           : t->runtime_us;
        if(cfg->on_thread && (!p || strcmp(p->name, t->name)))
          cfg->on_thread(cfg->ctx, t->tid, t->name);
        int sel;
        if(cfg->tid > 0 && t->tid != cfg->tid) sel = 0;
        else if(mode == MODE_PRECISE) sel = t->stat == TD_RUNNING;
        /* stopping the target makes every thread run briefly in the kernel
         * (~10-20us) to process the suspension; ignore that noise */
        else if(mode == MODE_WEIGHTED) sel = delta >= WEIGHTED_MIN_US;
        else sel = 1;
        t->inblock = sel ? (mode == MODE_WEIGHTED ? delta * 1000ull : period) : 0; /* scratch */
        if(sel) nsel++;
        else st->idle_skipped++;
      }
      if(!nsel) {
        /* nothing to look at: do not disturb the target */
        st->no_stop_rounds++;
        st->rounds++;
        goto swap;
      }
    }

    /* --- stop the world --- */
    if(kill(pid, SIGSTOP) < 0) { exited = (errno == ESRCH); break; }
    if(wait_stopped(pid, &exited)) break;
    uint64_t ts = now_ns();
    pc->gen++;

    if(mode == MODE_LWP) {
      get_threads(pid, cur, &approx);
      for(int i = 0; i < cur->n; i++) {
        thread_info_t *t = &cur->t[i];
        if(cfg->on_thread && !ttab_find(prev, t->tid)) cfg->on_thread(cfg->ctx, t->tid, t->name);
        if(cfg->tid > 0 && t->tid != cfg->tid) continue;
        emit(cfg, st, pc, s, t, ts - t0, period);
      }
    } else {
      for(int i = 0; i < cur->n; i++)
        if(cur->t[i].inblock) emit(cfg, st, pc, s, &cur->t[i], ts - t0, cur->t[i].inblock);
    }

    uint64_t stopped = now_ns() - ts;
    st->stop_ns_total += stopped;
    if(stopped > st->stop_ns_max) st->stop_ns_max = stopped;
    st->rounds++;

    if(pt_call(PT_CONTINUE, pid, (void *)1, 0) < 0) break;

  swap:;
    ttab_t *tmp = prev; prev = cur; cur = tmp;

  next_tick:
    if(cfg->on_tick && cfg->on_tick(cfg->ctx, (now_ns() - t0) / 1e9)) break;
    next += period;
    tnow = now_ns();
    if(next < tnow) next = tnow + period / 4;     /* we fell behind */
  }

  st->elapsed = (now_ns() - t0) / 1e9;
  st->exited = exited;
  st->approx = approx;
  rc = 0;
  detach(pid, &exited);
  g_attached_pid = 0;

out_free:
  free(prev);
  free(cur);
  free(pc);
  free(s);
  return rc;
}
