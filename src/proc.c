#include <errno.h>
#include <stddef.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>

#include "ps5perf.h"

/* ------------------------------------------------------- process info --- */

static void *
sysctl_alloc(int *mib, u_int miblen, size_t *len) {
  void *buf = NULL;

  for(int tries = 0; tries < 8; tries++) {
    if(sysctl(mib, miblen, NULL, len, NULL, 0)) return NULL;
    *len += *len / 4 + 4096;            /* threads may appear meanwhile */
    free(buf);
    if(!(buf = malloc(*len))) return NULL;
    if(!sysctl(mib, miblen, buf, len, NULL, 0)) return buf;
    if(errno != ENOMEM) break;
  }
  free(buf);
  return NULL;
}

/* process-wide totals (all threads, including exited ones) */
int
proc_totals(pid_t pid, thread_info_t *t, char *comm, size_t commlen) {
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  size_t len = 0;
  char *buf = sysctl_alloc(mib, 4, &len);

  if(!buf) return -1;
  struct kinfo_proc *ki = (struct kinfo_proc *)buf;
  /* The PS5's kinfo_proc is 8 bytes larger than FreeBSD's: the extra field
   * sits between ki_tid and ki_rusage (verified against getrusage()). */
  size_t ru_off = offsetof(struct kinfo_proc, ki_rusage);
  if(ki->ki_structsize >= (int)sizeof(struct kinfo_proc) + 8) ru_off += 8;
  const struct rusage *ru = (const struct rusage *)(buf + ru_off);
  memset(t, 0, sizeof *t);
  t->tid = ki->ki_tid;
  snprintf(t->name, sizeof t->name, "%s", ki->ki_comm);
  t->runtime_us = ki->ki_runtime;
  t->nvcsw = ru->ru_nvcsw;
  t->nivcsw = ru->ru_nivcsw;
  t->minflt = ru->ru_minflt;
  t->majflt = ru->ru_majflt;
  t->inblock = ru->ru_inblock;
  t->oublock = ru->ru_oublock;
  t->stat = ki->ki_stat;
  t->lastcpu = ki->ki_lastcpu;
  if(comm) snprintf(comm, commlen, "%s", ki->ki_comm);
  free(buf);
  return 0;
}

/* Per-thread info. The PS5 kernel does not implement KERN_PROC_INC_THREAD,
 * so threads are read from kernel memory (see kthread.c). */
int
proc_threads(pid_t pid, thread_info_t *out, int max, char *comm, size_t commlen) {
  thread_info_t tot;

  if(proc_totals(pid, &tot, comm, commlen)) return -1;
  return kthreads_list(pid, out, max);
}

int
proc_exists(pid_t pid) {
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  size_t len = 0;

  /* size query only: the PS5 kinfo_proc is larger than the SDK's struct */
  if(sysctl(mib, 4, NULL, &len, NULL, 0)) return 0;
  return len > 0;
}

int
proc_find_by_name(const char *name, pid_t *pid) {
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0 };
  size_t len = 0;
  char *buf = sysctl_alloc(mib, 4, &len);
  pid_t best = -1;
  pid_t me = getpid();

  if(!buf) return -1;
  for(char *p = buf; p < buf + len;) {
    struct kinfo_proc *ki = (struct kinfo_proc *)p;
    if(ki->ki_structsize <= 0) break;
    p += ki->ki_structsize;
    if(ki->ki_pid == me || ki->ki_stat == SZOMB) continue;
    if(!strcmp(ki->ki_comm, name) && ki->ki_pid > best) best = ki->ki_pid;
  }
  if(best < 0) {   /* fall back to prefix match */
    for(char *p = buf; p < buf + len;) {
      struct kinfo_proc *ki = (struct kinfo_proc *)p;
      if(ki->ki_structsize <= 0) break;
      p += ki->ki_structsize;
      if(ki->ki_pid == me || ki->ki_stat == SZOMB) continue;
      if(!strncmp(ki->ki_comm, name, strlen(name)) && ki->ki_pid > best) best = ki->ki_pid;
    }
  }
  free(buf);
  if(best < 0) return -1;
  *pid = best;
  return 0;
}

/* ------------------------------------------------------------ ptrace ---- */

/* The PS5 kernel only lets processes holding a debugger auth id use
 * ptrace(2). The payload runs as a jailbroken process with kernel r/w, so
 * we simply switch our ucred auth id once at start-up. */
#define DEBUGGER_AUTHID 0x4800000000010003ul

int
pt_init(void) {
  pid_t me = getpid();
  uint64_t authid = kernel_get_ucred_authid(me);

  if(authid == DEBUGGER_AUTHID) return 0;
  if(kernel_set_ucred_authid(me, DEBUGGER_AUTHID)) {
    klogf("unable to set debugger authid (was %lx)", authid);
    return -1;
  }
  return 0;
}

int
pt_call(int req, pid_t pid, void *addr, int data) {
  return (int)syscall(SYS_ptrace, req, pid, addr, data);
}

int
pt_attach(pid_t pid) {
  int status;

  if(pt_call(PT_ATTACH, pid, 0, 0) < 0) return -1;
  for(;;) {
    pid_t r = waitpid(pid, &status, 0);
    if(r < 0 && errno == EINTR) continue;
    if(r < 0) return -1;
    break;
  }
  return 0;
}

int
pt_detach(pid_t pid) {
  return pt_call(PT_DETACH, pid, (void *)1, 0);
}

int
pt_read(pid_t pid, uint64_t addr, void *buf, size_t len) {
  struct ptrace_io_desc io = {
    .piod_op = PIOD_READ_D,
    .piod_offs = (void *)addr,
    .piod_addr = buf,
    .piod_len = len,
  };

  if(pt_call(PT_IO, pid, &io, 0) < 0) return -1;
  return io.piod_len == len ? 0 : -1;
}
