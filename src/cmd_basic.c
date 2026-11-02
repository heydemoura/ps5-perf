#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <ps5/kernel.h>

#include "ps5perf.h"

typedef struct app_info {
  uint32_t app_id;
  uint64_t unknown1;
  uint32_t app_type;
  char     title_id[10];
  char     unknown2[0x3c];
} app_info_t;

int sceKernelGetAppInfo(pid_t pid, app_info_t *info);

int
cmd_help(int argc, char **argv, out_t *o) {
  (void)argc; (void)argv;
  out_printf(o,
    "\n usage: <command> [<options>]\n\n"
    " The most commonly used ps5-perf commands are:\n"
    "   ps        List processes (pid, threads, cpu time, title id)\n"
    "   threads   List threads of a process            threads -p <pid|name>\n"
    "   maps      List loaded modules of a process     maps -p <pid|name>\n"
    "   list      List available events\n"
    "   stat      Run a counter session                stat -p <pid|name> [-d sec] [-I ms] [--per-thread]\n"
    "   record    Sample, stream raw records (for the host tool)\n"
    "             record -p <pid|name> [-F hz] [-g] [-d sec] [-t tid] [--off-cpu] [--no-syms]\n"
    "   script    Sample, stream 'perf script' compatible text (same options as record)\n"
    "   report    Sample, then print a 'perf report --stdio' style profile\n"
    "             report -p <pid|name> [-F hz] [-g] [-d sec] [-s comm,dso,sym|tid] [-n lines] [--children]\n"
    "   top       Live profile, refreshed every -I ms   top -p <pid|name> [-F hz] [-I ms] [-n lines]\n"
    "   version   Show version\n"
    "   quit      Close this connection\n"
    "   shutdown  Terminate the ps5-perf payload\n\n"
    " Options:\n"
    "   -p, --pid        target pid or process name (e.g. eboot.bin)\n"
    "   -F, --freq       sampling frequency in Hz (default 99, max 2000)\n"
    "   -g               record call graphs (frame pointer unwinding)\n"
    "   -d, --duration   seconds to run (or '-- sleep N'); default: until you send a newline\n"
    "   -t, --tid        restrict to one thread\n"
    "   --off-cpu        sample all threads, running or not (wall-clock profile)\n"
    "   --weighted       sample every thread that ran since the last tick, weighted by\n"
    "                    its run time (more samples, less precise attribution)\n"
    "   --max-stack N    maximum call chain depth (default %d)\n\n"
    " Sending any input while a command runs stops it.\n\n", DEFAULT_STACK);
  return 0;
}

int
cmd_version(int argc, char **argv, out_t *o) {
  (void)argc; (void)argv;
  uint32_t fw = kernel_get_fw_version();
  out_printf(o, "ps5-perf version %s (fw %x.%02x, pid %d, port %d)\n", PS5PERF_VERSION,
             (fw >> 24) & 0xff, (fw >> 16) & 0xff, getpid(), PS5PERF_PORT);
  out_printf(o, "kernel thread accounting: %s\n", kthreads_status());
  return 0;
}

int
cmd_list(int argc, char **argv, out_t *o) {
  (void)argc; (void)argv;
  out_printf(o,
    "\nList of pre-defined events (to be used in -e):\n\n"
    "  cpu-clock                                          [Software event, sampling]\n"
    "  task-clock                                         [Software event, stat]\n"
    "  context-switches OR cs                             [Software event, stat]\n"
    "  involuntary-context-switches                       [Software event, stat]\n"
    "  page-faults OR faults                              [Software event, stat]\n"
    "  major-faults                                       [Software event, stat]\n"
    "  minor-faults                                       [Software event, stat]\n"
    "  block-input / block-output                         [Software event, stat]\n\n"
    "  Hardware events (cycles, instructions, cache-misses, ...) are not\n"
    "  available: the PS5 kernel exposes no PMU interface to user space.\n\n");
  return 0;
}

static const char *
state_name(int s) {
  static const char *n[] = { "?", "IDL", "RUN", "SLP", "STP", "ZMB", "WAI", "LCK" };
  return (s >= 0 && s < 8) ? n[s] : "?";
}

int
cmd_ps(int argc, char **argv, out_t *o) {
  (void)argc; (void)argv;
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0 };
  size_t len = 0;
  char *buf = NULL;

  if(sysctl(mib, 4, NULL, &len, NULL, 0) || !(buf = malloc(len += 16384)) ||
     sysctl(mib, 4, buf, &len, NULL, 0)) {
    out_printf(o, "error: sysctl kern.proc failed\n");
    free(buf);
    return -1;
  }

  out_printf(o, "%7s %7s %4s %5s %12s %9s  %-9s  %s\n",
             "PID", "PPID", "STAT", "THR", "CPU-TIME(s)", "RSS(MiB)", "TITLE", "COMMAND");
  for(char *p = buf; p < buf + len;) {
    struct kinfo_proc *ki = (struct kinfo_proc *)p;
    app_info_t ai;
    if(ki->ki_structsize <= 0) break;
    p += ki->ki_structsize;
    memset(&ai, 0, sizeof ai);
    if(sceKernelGetAppInfo(ki->ki_pid, &ai)) memset(&ai, 0, sizeof ai);
    ai.title_id[9] = 0;
    out_printf(o, "%7d %7d %4s %5d %12.2f %9.1f  %-9s  %s\n",
               ki->ki_pid, ki->ki_ppid, state_name(ki->ki_stat), ki->ki_numthreads,
               ki->ki_runtime / 1e6, ki->ki_rssize * (double)PAGE_SIZE / (1024 * 1024),
               ai.title_id[0] ? ai.title_id : "-", ki->ki_comm);
  }
  free(buf);
  return 0;
}

int
cmd_threads(int argc, char **argv, out_t *o) {
  opts_t op;
  char comm[64] = "";
  thread_info_t *t = calloc(MAX_THREADS, sizeof *t);
  int n;

  if(!t) return -1;
  if(opts_parse(argc, argv, &op, o) || resolve_target(&op, o)) { free(t); return -1; }
  if((n = proc_threads(op.pid, t, MAX_THREADS, comm, sizeof comm)) < 0) {
    out_printf(o, "(%s)\n", kthreads_status());
    out_printf(o, "error: unable to query threads of %d: %s\n", op.pid, strerror(errno));
    free(t);
    return -1;
  }
  out_printf(o, "process %d (%s), %d threads\n", op.pid, comm, n);
  static const char *tds[] = { "INACT", "INHIB", "CANRN", "RUNQ", "RUN" };
  out_printf(o, "%8s %5s %12s %10s %10s %10s  %s\n", "TID", "STATE",
             "CPU-TIME(ms)", "VCSW", "IVCSW", "FAULTS", "NAME");
  for(int i = 0; i < n; i++)
    out_printf(o, "%8d %5s %12.1f %10lu %10lu %10lu  %s\n", t[i].tid,
               t[i].stat >= 0 && t[i].stat <= 4 ? tds[t[i].stat] : "?",
               t[i].runtime_us / 1e3, (unsigned long)t[i].nvcsw,
               (unsigned long)t[i].nivcsw, (unsigned long)(t[i].minflt + t[i].majflt), t[i].name);
  free(t);
  return 0;
}

int
cmd_maps(int argc, char **argv, out_t *o) {
  opts_t op;
  modlist_t ml;

  if(opts_parse(argc, argv, &op, o) || resolve_target(&op, o)) return -1;
  if(modules_load(op.pid, &ml, 1, 0)) {
    out_printf(o, "error: unable to read module list of %d\n", op.pid);
    return -1;
  }
  out_printf(o, "%-16s %-16s %-16s %7s %7s  %-32s %s\n", "BASE", "TEXT-END", "MAP-END",
             "FUNCS", "EXPORTS", "NAME", "PATH");
  for(int i = 0; i < ml.n; i++) {
    module_t *m = &ml.mods[i];
    out_printf(o, "%016lx %016lx %016lx %7d %7d  %-32s %s\n", (unsigned long)m->base,
               (unsigned long)m->text_end, (unsigned long)m->map_end, m->nfuncs, m->n_dynsym,
               m->name, m->path);
  }
  modules_free(&ml);
  return 0;
}
