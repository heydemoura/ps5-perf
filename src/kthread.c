/* Per-thread accounting straight from kernel `struct thread`.
 *
 * The PS5 kernel rejects sysctl(KERN_PROC_INC_THREAD), so per-thread run
 * time is not available through the usual FreeBSD interfaces. We have
 * kernel r/w though, so we walk proc->p_threads ourselves. The layout of
 * struct thread differs between firmwares, so instead of hard-coding
 * offsets we calibrate at start-up against a thread we control:
 *
 *   - spawn a worker with a known name, let it burn known amounts of CPU,
 *     and snapshot its struct thread while it is blocked
 *   - td_tid / td_name:   search for the worker's tid and name
 *   - td_ru:              match the rusage counters getrusage(RUSAGE_THREAD)
 *                         reported (nvcsw/nivcsw/minflt at fixed offsets)
 *   - td_runtime:         the u64 that grows in proportion to the worker's
 *                         CLOCK_THREAD_CPUTIME_ID across three snapshots;
 *                         the ratio also yields the cpu tick rate.
 */
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/thr.h>

#include <ps5/kernel.h>

#include "ps5perf.h"

#define SNAP_SIZE      0x900
#define P_THREADS_OFF  0x10        /* struct proc: after LIST_ENTRY p_list */
#define TD_PROC_OFF    0x08        /* struct thread: after td_lock */
#define CALIB_NAME     "ps5perf-calib"

/* struct rusage field offsets (FreeBSD amd64) */
#define RU_MINFLT   64
#define RU_MAJFLT   72
#define RU_INBLOCK  96
#define RU_OUBLOCK 104
#define RU_NVCSW   128
#define RU_NIVCSW  136

static struct {
  int    done, ok;
  int    plist, tid, name, runtime, ru;
  int    state;                   /* td_state (int) */
  double ticks_per_us;
  char   msg[160];
} g_td;

static pthread_mutex_t g_td_lock = PTHREAD_MUTEX_INITIALIZER;

static uint8_t *
find_bytes(uint8_t *hay, size_t hlen, const char *needle, size_t nlen) {
  for(size_t i = 0; i + nlen <= hlen; i++)
    if(!memcmp(hay + i, needle, nlen)) return hay + i;
  return NULL;
}

static int
kptr_ok(uint64_t p) {
  return p >= 0xffff800000000000ull && p < 0xfffffffffffff000ull && !(p & 7);
}

/* ------------------------------------------------------- calibration -- */

typedef struct calib {
  sem_t           ready, go;
  long            tid;
  struct timespec cpu[3];
  struct rusage   ru[3];
  volatile int    spinning, stop;
} calib_t;

/* FreeBSD enum td_states */
#define TDS_INHIBITED 1
#define TDS_CAN_RUN   2
#define TDS_RUNQ      3
#define TDS_RUNNING   4

static void
burn_ms(int ms) {
  struct timespec a, b;
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &a);
  do {
    for(volatile int i = 0; i < 20000; i++) { }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &b);
  } while((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < ms);
}

static void *
calib_worker(void *arg) {
  calib_t *c = arg;
  static const int ms[3] = { 30, 60, 40 };

  pthread_set_name_np(pthread_self(), CALIB_NAME);
  thr_self(&c->tid);
  for(int ph = 0; ph < 3; ph++) {
    burn_ms(ms[ph]);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c->cpu[ph]);
    /* no getrusage in the last phase: getrusage() folds td_runtime into
     * td_rux, and we want rux_runtime to go stale so it is not mistaken
     * for td_runtime */
    if(ph < 2) getrusage(RUSAGE_THREAD, &c->ru[ph]);
    sem_post(&c->ready);
    sem_wait(&c->go);
  }
  /* final phase: stay on-CPU so td_state can be identified */
  c->spinning = 1;
  while(!c->stop) { }
  return NULL;
}

static int
snapshot_by_tid(intptr_t kproc, long tid, int plist, uint8_t *snap, uint64_t *td_out) {
  uint64_t td = 0;

  if(kernel_copyout(kproc + P_THREADS_OFF, &td, 8) < 0) return -1;
  for(int i = 0; i < 64 && kptr_ok(td); i++) {
    if(kernel_copyout(td, snap, SNAP_SIZE) < 0) return -1;
    if(*(uint64_t *)(snap + TD_PROC_OFF) != (uint64_t)kproc) return -1;
    for(int o = 0; o + 4 <= SNAP_SIZE; o += 4) {
      if(*(int32_t *)(snap + o) == (int32_t)tid &&
         find_bytes(snap, SNAP_SIZE, CALIB_NAME, sizeof(CALIB_NAME) - 1)) {
        *td_out = td;
        return 0;
      }
    }
    td = *(uint64_t *)(snap + plist);
  }
  return -1;
}

static int
calibrate(void) {
  intptr_t kproc = kernel_get_proc(getpid());
  uint8_t *snap[3] = { malloc(SNAP_SIZE), malloc(SNAP_SIZE), malloc(SNAP_SIZE) };
  calib_t c;
  pthread_t th;
  uint64_t td = 0;
  int rc = -1;

  memset(&c, 0, sizeof c);
  if(!kproc || !snap[0] || !snap[1] || !snap[2]) {
    snprintf(g_td.msg, sizeof g_td.msg, "no proc / oom");
    goto out;
  }
  sem_init(&c.ready, 0, 0);
  sem_init(&c.go, 0, 0);
  if(pthread_create(&th, NULL, calib_worker, &c)) {
    snprintf(g_td.msg, sizeof g_td.msg, "pthread_create failed");
    goto out;
  }

  /* find td_plist: the TAILQ link whose successor also points back to us */
  g_td.plist = -1;
  for(int ph = 0; ph < 3; ph++) {
    sem_wait(&c.ready);
    sleep_ns(3000000);                 /* make sure the worker is switched out */
    if(ph == 0) {
      uint64_t first = 0;
      uint8_t buf[SNAP_SIZE];
      kernel_copyout(kproc + P_THREADS_OFF, &first, 8);
      if(kptr_ok(first) && kernel_copyout(first, buf, SNAP_SIZE) >= 0 &&
         *(uint64_t *)(buf + TD_PROC_OFF) == (uint64_t)kproc) {
        for(int o = 0x10; o <= 0x40 && g_td.plist < 0; o += 8) {
          uint64_t nx = *(uint64_t *)(buf + o), p2 = 0;
          if(!kptr_ok(nx)) continue;
          if(kernel_copyout(nx + TD_PROC_OFF, &p2, 8) >= 0 && p2 == (uint64_t)kproc)
            g_td.plist = o;
        }
      }
      if(g_td.plist < 0 ||
         snapshot_by_tid(kproc, c.tid, g_td.plist, snap[0], &td)) {
        snprintf(g_td.msg, sizeof g_td.msg, "thread list layout not recognised (plist=%d)",
                 g_td.plist);
        g_td.plist = -1;
      }
    } else if(g_td.plist >= 0) {
      kernel_copyout(td, snap[ph], SNAP_SIZE);
    }
    sem_post(&c.go);
  }

  /* td_state: compare snapshots taken while the worker is
   * blocked (phases 0-2) with ones taken while it spins on another CPU */
  g_td.state = -1;
  while(!c.spinning) sleep_ns(100000);
  {
    /* a field qualifies only if it matches in every running snapshot */
    enum { NRUN = 12 };
    static uint8_t run[NRUN][SNAP_SIZE];
    int nrun = 0;
    for(int tries = 0; tries < 60 && nrun < NRUN && g_td.plist >= 0; tries++) {
      if(kernel_copyout(td, run[nrun], SNAP_SIZE) < 0) break;
      nrun++;
      sleep_ns(700000);
    }
    /* td_state: TDS_RUNNING while spinning in (nearly) all snapshots - the
     * worker can be preempted, so allow a few RUNQ/CAN_RUN readings */
    for(int o = 0; o + 4 <= SNAP_SIZE && g_td.state < 0 && nrun; o += 4) {
      int ok = 1, running = 0;
      for(int ph = 0; ph < 3 && ok; ph++) ok = *(int32_t *)(snap[ph] + o) == TDS_INHIBITED;
      for(int i = 0; i < nrun && ok; i++) {
        int32_t v = *(int32_t *)(run[i] + o);
        if(v == TDS_RUNNING) running++;
        else if(v != TDS_RUNQ && v != TDS_CAN_RUN) ok = 0;
      }
      if(ok && running * 4 >= nrun * 3) g_td.state = o;
    }
  }
  c.stop = 1;
  pthread_join(th, NULL);
  if(g_td.plist < 0) goto out;

  /* td_tid and td_name */
  g_td.tid = g_td.name = -1;
  for(int o = 0; o + 4 <= SNAP_SIZE && g_td.tid < 0; o += 4)
    if(*(int32_t *)(snap[0] + o) == (int32_t)c.tid) g_td.tid = o;
  uint8_t *nm = find_bytes(snap[0], SNAP_SIZE, CALIB_NAME, sizeof(CALIB_NAME) - 1);
  if(nm) g_td.name = (int)(nm - snap[0]);

  /* td_ru */
  g_td.ru = -1;
  for(int b = 0; b + RU_NIVCSW + 8 <= SNAP_SIZE && g_td.ru < 0; b += 8) {
    int good = 1;
    for(int ph = 0; ph < 2 && good; ph++) {
      const uint64_t *v = (const uint64_t *)(snap[ph] + b);
      const struct rusage *r = &c.ru[ph];
#define NEAR(off, want) (v[(off) / 8] >= (uint64_t)(want) && v[(off) / 8] <= (uint64_t)(want) + 4)
      good = NEAR(RU_NVCSW, r->ru_nvcsw) && NEAR(RU_NIVCSW, r->ru_nivcsw) &&
             NEAR(RU_MINFLT, r->ru_minflt) && NEAR(RU_MAJFLT, r->ru_majflt);
#undef NEAR
    }
    if(good && c.ru[1].ru_nvcsw > c.ru[0].ru_nvcsw) g_td.ru = b;
  }

  /* td_runtime: grows proportionally to thread cpu time */
  double cns[3];
  for(int ph = 0; ph < 3; ph++) cns[ph] = c.cpu[ph].tv_sec * 1e9 + c.cpu[ph].tv_nsec;
  int best = -1;
  double best_r = 0;
  for(int o = 0; o + 8 <= SNAP_SIZE; o += 8) {
    uint64_t v0 = *(uint64_t *)(snap[0] + o), v1 = *(uint64_t *)(snap[1] + o),
             v2 = *(uint64_t *)(snap[2] + o);
    if(!(v0 < v1 && v1 < v2)) continue;
    double r01 = (v1 - v0) / (cns[1] - cns[0]);
    double r12 = (v2 - v1) / (cns[2] - cns[1]);
    double rab = v2 / cns[2];
    if(r01 < 1e-4 || r01 > 1e3) continue;
    if(r12 < r01 * 0.85 || r12 > r01 * 1.15) continue;
    if(rab < r01 * 0.85 || rab > r01 * 1.15) continue;
    /* prefer td_runtime = td_ru + sizeof(rusage) + sizeof(rusage_ext) + 8 */
    if(best < 0 || (g_td.ru >= 0 && o == g_td.ru + 144 + 56 + 8)) { best = o; best_r = rab; }
  }
  g_td.runtime = best;
  g_td.ticks_per_us = best_r * 1000.0;

  if(g_td.tid < 0 || g_td.runtime < 0) {
    snprintf(g_td.msg, sizeof g_td.msg, "calibration failed: tid@%d name@%d runtime@%d ru@%d",
             g_td.tid, g_td.name, g_td.runtime, g_td.ru);
    goto out;
  }
  snprintf(g_td.msg, sizeof g_td.msg,
           "struct thread: plist@0x%x tid@0x%x name@0x%x runtime@0x%x ru@0x%x state@0x%x, "
           "%.1f ticks/us", g_td.plist, g_td.tid, g_td.name, g_td.runtime, g_td.ru,
           g_td.state, g_td.ticks_per_us);
  rc = 0;

out:
  for(int i = 0; i < 3; i++) free(snap[i]);
  return rc;
}

int
kthreads_init(void) {
  pthread_mutex_lock(&g_td_lock);
  if(!g_td.done) {
    g_td.ok = !calibrate();
    g_td.done = 1;
    klogf("%s", g_td.msg);
  }
  pthread_mutex_unlock(&g_td_lock);
  return g_td.ok ? 0 : -1;
}

int
kthreads_have_state(void) {
  return g_td.ok && g_td.state >= 0;
}

const char *
kthreads_status(void) {
  return g_td.msg;
}

int
kthreads_list(pid_t pid, thread_info_t *out, int max) {
  intptr_t kproc;
  uint64_t td = 0;
  int n = 0;
  int span;
  uint8_t buf[SNAP_SIZE];

  if(kthreads_init()) return -1;
  if(!(kproc = kernel_get_proc(pid))) return -1;
  if(kernel_copyout(kproc + P_THREADS_OFF, &td, 8) < 0) return -1;

  span = g_td.plist + 8;
  if(g_td.tid + 4 > span) span = g_td.tid + 4;
  if(g_td.name + 32 > span) span = g_td.name + 32;
  if(g_td.runtime + 8 > span) span = g_td.runtime + 8;
  if(g_td.ru >= 0 && g_td.ru + 144 > span) span = g_td.ru + 144;
  if(g_td.state + 4 > span) span = g_td.state + 4;
  if(span < TD_PROC_OFF + 8) span = TD_PROC_OFF + 8;

  while(n < max && kptr_ok(td)) {
    if(kernel_copyout(td, buf, span) < 0) break;
    if(*(uint64_t *)(buf + TD_PROC_OFF) != (uint64_t)kproc) break;  /* list changed */

    thread_info_t *t = &out[n++];
    memset(t, 0, sizeof *t);
    t->tid = *(int32_t *)(buf + g_td.tid);
    if(g_td.name >= 0) {
      memcpy(t->name, buf + g_td.name, sizeof(t->name) - 1);
      t->name[sizeof(t->name) - 1] = 0;
    }
    t->runtime_us = (uint64_t)(*(uint64_t *)(buf + g_td.runtime) / g_td.ticks_per_us);
    if(g_td.ru >= 0) {
      const uint8_t *r = buf + g_td.ru;
      t->nvcsw = *(uint64_t *)(r + RU_NVCSW);
      t->nivcsw = *(uint64_t *)(r + RU_NIVCSW);
      t->minflt = *(uint64_t *)(r + RU_MINFLT);
      t->majflt = *(uint64_t *)(r + RU_MAJFLT);
      t->inblock = *(uint64_t *)(r + RU_INBLOCK);
      t->oublock = *(uint64_t *)(r + RU_OUBLOCK);
    }
    t->stat = g_td.state >= 0 ? *(int32_t *)(buf + g_td.state) : -1;
    t->oncpu = -1;          /* not reliably identifiable, not reported */
    t->lastcpu = -1;
    td = *(uint64_t *)(buf + g_td.plist);
  }
  return n;
}
