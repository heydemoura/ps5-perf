/* ps5-perf: a perf(1)-style sampling profiler payload for the PlayStation 5.
 *
 * The command layout mirrors linux/tools/perf/perf.c (a table of
 * sub-commands dispatched by name), but the event sources are
 * re-implemented on top of what the PS5 (FreeBSD 11 based) kernel offers:
 *
 *   - cpu-clock sampling:  ptrace stop/inspect/continue of the target,
 *                          weighted by each thread's on-CPU time delta
 *   - call graphs:         frame-pointer (rbp chain) unwinding
 *   - software counters:   per-thread rusage/runtime from sysctl(KERN_PROC)
 *   - symbols:             kernel dynlib objects (module map + dynsym NIDs)
 *                          plus .eh_frame_hdr function boundaries
 *
 * Linux's perf_event_open(2) does not exist on the PS5, so this is a
 * re-implementation rather than a port.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define PS5PERF_VERSION     "1.0.0"
#ifndef PS5PERF_PORT
#define PS5PERF_PORT        9077
#endif

#define MAX_THREADS         1024
#define MAX_STACK           128
#define DEFAULT_STACK       64

/* ------------------------------------------------------------ output ---- */

typedef struct out {
  int    fd;
  int    err;           /* set once a write fails (client went away) */
  int    hold;          /* never flush implicitly (target may be stopped) */
  size_t len, cap;
  char  *buf;
} out_t;

#define OUT_FLUSH_AT (64 * 1024)

int  out_init(out_t *o, int fd);
void out_free(out_t *o);
void out_printf(out_t *o, const char *fmt, ...)
  __attribute__((format(printf, 2, 3)));
void out_write(out_t *o, const void *data, size_t len);
void out_flush(out_t *o);

/* returns 1 if the client asked us to stop (sent a line / closed socket) */
int  client_wants_stop(int fd);

double   now_sec(void);
uint64_t now_ns(void);
void     sleep_ns(uint64_t ns);

/* -------------------------------------------------------------- args ---- */

typedef struct opts {
  pid_t    pid;
  char     comm[64];      /* when -p was given a process name */
  pid_t    tid;           /* -t: restrict to one thread */
  int      freq;          /* -F */
  double   duration;      /* -d or trailing "sleep N" */
  int      callgraph;     /* -g */
  int      max_stack;
  int      off_cpu;       /* --off-cpu: also sample sleeping threads */
  int      weighted;      /* --weighted: runtime-delta sampling */
  int      per_thread;    /* stat --per-thread */
  int      interval_ms;   /* stat/top -I */
  int      top_n;         /* report/top -n */
  int      no_syms;       /* record --no-syms */
  char     sort[32];      /* report --sort sym|dso|comm|tid */
  int      children;      /* report --children */
} opts_t;

int  opts_parse(int argc, char **argv, opts_t *o, out_t *out);
int  resolve_target(opts_t *o, out_t *out);

/* ------------------------------------------------------- process info --- */

typedef struct thread_info {
  pid_t    tid;
  char     name[33];
  uint64_t runtime_us;
  uint64_t nvcsw, nivcsw;
  uint64_t minflt, majflt;
  uint64_t inblock, oublock;
  int      stat;          /* kernel td_state (4 = running), -1 unknown */
  int      oncpu;         /* cpu the thread is running on, -1 if none */
  int      lastcpu;
} thread_info_t;

int  proc_threads(pid_t pid, thread_info_t *out, int max, char *comm, size_t commlen);
int  proc_totals(pid_t pid, thread_info_t *t, char *comm, size_t commlen);
int  proc_find_by_name(const char *name, pid_t *pid);
int  kthreads_init(void);
const char *kthreads_status(void);
int  kthreads_have_state(void);   /* td_state known: precise on-CPU sampling */
#define TD_RUNNING 4
int  kthreads_list(pid_t pid, thread_info_t *out, int max);
int  proc_exists(pid_t pid);

/* ------------------------------------------------------------ ptrace ---- */

int  pt_init(void);
int  pt_call(int req, pid_t pid, void *addr, int data);
int  pt_attach(pid_t pid);
int  pt_detach(pid_t pid);
int  pt_read(pid_t pid, uint64_t addr, void *buf, size_t len);

/* ------------------------------------------------------- module map ----- */

typedef struct func {
  uint64_t start;         /* module relative */
  uint32_t size;
  int32_t  name;          /* offset into module string pool, -1 = none */
} func_t;

typedef struct module {
  uint64_t base;          /* mapbase (absolute) */
  uint64_t text_end;      /* absolute */
  uint64_t map_end;       /* absolute */
  char     name[64];
  char     path[256];
  func_t  *funcs;         /* sorted by start */
  int      nfuncs;
  char    *strpool;
  size_t   strpool_len;
  int      n_eh;          /* how many funcs came from .eh_frame_hdr */
  int      n_dynsym;      /* how many named funcs came from dynsym */
} module_t;

typedef struct modlist {
  module_t *mods;
  int       n;
} modlist_t;

int  modules_load(pid_t pid, modlist_t *ml, int with_funcs, int attached);
void modules_free(modlist_t *ml);
const module_t *module_find(const modlist_t *ml, uint64_t addr);
const func_t   *func_find(const module_t *m, uint64_t addr);
const char     *func_name(const module_t *m, const func_t *f, char *buf, size_t len);
/* "sym+0xoff" / "module+0xoff" / "[unknown]" */
void symbolize(const modlist_t *ml, uint64_t addr, char *sym, size_t symlen,
               const char **dso, uint64_t *symoff);

/* ----------------------------------------------------------- sampler ---- */

typedef struct sample {
  uint64_t     time_ns;     /* since start of recording */
  pid_t        tid;
  const char  *tname;
  uint64_t     weight_ns;   /* on-CPU time represented by this sample */
  int          on_cpu;
  int          cpu;
  int          nips;
  uint64_t     ips[MAX_STACK];
} sample_t;

typedef struct sampler_stats {
  uint64_t rounds;
  uint64_t samples;
  uint64_t idle_skipped;
  uint64_t stop_ns_total;   /* time the target spent stopped by us */
  uint64_t stop_ns_max;
  double   elapsed;
  int      exited;
  int      approx;          /* no per-thread run times available */
  int      mode;            /* 0 precise, 1 weighted, 2 off-cpu, 3 lwp fallback */
  uint64_t no_stop_rounds;  /* ticks where nothing ran, target not stopped */
} sampler_stats_t;

typedef struct sampler_cfg {
  pid_t   pid;
  pid_t   tid;
  int     freq;
  double  duration;          /* <= 0: until client stops */
  int     callgraph;
  int     max_stack;
  int     off_cpu;
  int     weighted;
  int     client_fd;
  const modlist_t *mods;     /* optional, used to validate unwound frames */
  void  (*on_sample)(void *ctx, const sample_t *s);
  void  (*on_thread)(void *ctx, pid_t tid, const char *name);
  int   (*on_tick)(void *ctx, double t);   /* return != 0 to stop */
  void   *ctx;
} sampler_cfg_t;

int sampler_run(sampler_cfg_t *cfg, sampler_stats_t *st, char *err, size_t errlen);
const char *sampler_mode_name(int mode);
const char *sampler_mode_short(int mode);

/* set by `shutdown`; running sessions finish and detach */
extern volatile int g_shutdown;
/* pid currently attached by the sampler (0 = none), for the crash handler */
extern volatile pid_t g_attached_pid;
void sampler_emergency_detach(void);

/* ---------------------------------------------------------- commands ---- */

int cmd_help(int argc, char **argv, out_t *o);
int cmd_version(int argc, char **argv, out_t *o);
int cmd_list(int argc, char **argv, out_t *o);
int cmd_ps(int argc, char **argv, out_t *o);
int cmd_threads(int argc, char **argv, out_t *o);
int cmd_maps(int argc, char **argv, out_t *o);
int cmd_stat(int argc, char **argv, out_t *o);
int cmd_record(int argc, char **argv, out_t *o);
int cmd_script(int argc, char **argv, out_t *o);
int cmd_report(int argc, char **argv, out_t *o);
int cmd_top(int argc, char **argv, out_t *o);

/* NID -> symbol name table generated from the SDK stubs at build time */
const char *nid_lookup(const char *nid);

void klogf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void notify(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
