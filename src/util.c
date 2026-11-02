#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#include <ps5/klog.h>

#include "ps5perf.h"

/* ------------------------------------------------------------ output ---- */

int
out_init(out_t *o, int fd) {
  memset(o, 0, sizeof *o);
  o->fd = fd;
  o->cap = 2 * OUT_FLUSH_AT;
  o->buf = malloc(o->cap);
  return o->buf ? 0 : -1;
}

void
out_free(out_t *o) {
  free(o->buf);
  o->buf = NULL;
}

void
out_flush(out_t *o) {
  size_t off = 0;

  while(!o->err && off < o->len) {
    ssize_t n = send(o->fd, o->buf + off, o->len - off, MSG_NOSIGNAL);
    if(n < 0) {
      if(errno == EINTR) continue;
      o->err = errno;
      break;
    }
    off += (size_t)n;
  }
  o->len = 0;
}

/* Buffered write. While `hold` is set (the sampler may have the target
 * stopped) we never block on the socket: the buffer grows instead and is
 * flushed by the caller once the target runs again. */
void
out_write(out_t *o, const void *data, size_t len) {
  if(o->err) return;
  if(o->len + len > o->cap) {
    if(!o->hold) out_flush(o);
    if(o->len + len > o->cap) {
      size_t ncap = o->cap;
      while(o->len + len > ncap) ncap *= 2;
      if(ncap > (256u << 20)) { o->err = ENOMEM; return; }
      char *nb = realloc(o->buf, ncap);
      if(!nb) { o->err = ENOMEM; return; }
      o->buf = nb;
      o->cap = ncap;
    }
  }
  memcpy(o->buf + o->len, data, len);
  o->len += len;
  if(!o->hold && o->len >= OUT_FLUSH_AT) out_flush(o);
}

void
out_printf(out_t *o, const char *fmt, ...) {
  char tmp[4096];
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  if(n < 0) return;
  if((size_t)n >= sizeof tmp) n = sizeof(tmp) - 1;
  out_write(o, tmp, (size_t)n);
}

int
client_wants_stop(int fd) {
  struct pollfd p = { .fd = fd, .events = POLLIN };
  char junk[256];

  if(poll(&p, 1, 0) <= 0) return 0;
  if(p.revents & (POLLHUP | POLLERR | POLLNVAL)) return 1;
  if(p.revents & POLLIN) {
    ssize_t n = recv(fd, junk, sizeof junk, MSG_DONTWAIT);
    if(n <= 0) return 1;   /* EOF */
    return 1;              /* any input means "stop" */
  }
  return 0;
}

/* -------------------------------------------------------------- time ---- */

uint64_t
now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

double
now_sec(void) {
  return now_ns() / 1e9;
}

void
sleep_ns(uint64_t ns) {
  struct timespec ts = { (time_t)(ns / 1000000000ull), (long)(ns % 1000000000ull) };
  while(nanosleep(&ts, &ts) < 0 && errno == EINTR) { }
}

/* ------------------------------------------------------------- logging -- */

void
klogf(const char *fmt, ...) {
  char buf[1024];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  klog_printf("[ps5-perf] %s\n", buf);
}

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

void
notify(const char *fmt, ...) {
  notify_request_t req;
  va_list ap;

  memset(&req, 0, sizeof req);
  va_start(ap, fmt);
  vsnprintf(req.message, sizeof req.message, fmt, ap);
  va_end(ap);
  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}

/* -------------------------------------------------------------- args ---- */

static int
need(int i, int argc, char **argv, out_t *out) {
  if(i + 1 >= argc) {
    out_printf(out, "error: option %s requires an argument\n", argv[i]);
    return 0;
  }
  return 1;
}

int
opts_parse(int argc, char **argv, opts_t *o, out_t *out) {
  memset(o, 0, sizeof *o);
  o->pid = -1;
  o->tid = -1;
  o->freq = 99;
  o->max_stack = DEFAULT_STACK;
  o->top_n = 30;
  o->interval_ms = 0;

  for(int i = 1; i < argc; i++) {
    const char *a = argv[i];

    if(!strcmp(a, "-p") || !strcmp(a, "--pid")) {
      if(!need(i, argc, argv, out)) return -1;
      const char *v = argv[++i];
      char *end;
      long pid = strtol(v, &end, 10);
      if(*v && !*end) o->pid = (pid_t)pid;
      else snprintf(o->comm, sizeof o->comm, "%s", v);
    } else if(!strcmp(a, "-t") || !strcmp(a, "--tid")) {
      if(!need(i, argc, argv, out)) return -1;
      o->tid = (pid_t)atoi(argv[++i]);
    } else if(!strcmp(a, "-F") || !strcmp(a, "--freq")) {
      if(!need(i, argc, argv, out)) return -1;
      o->freq = atoi(argv[++i]);
    } else if(!strcmp(a, "-d") || !strcmp(a, "--duration")) {
      if(!need(i, argc, argv, out)) return -1;
      o->duration = atof(argv[++i]);
    } else if(!strcmp(a, "-g") || !strcmp(a, "--call-graph")) {
      o->callgraph = 1;
      /* accept "--call-graph fp" / "-g fp" like perf */
      if(i + 1 < argc && !strcmp(argv[i + 1], "fp")) i++;
    } else if(!strcmp(a, "--max-stack")) {
      if(!need(i, argc, argv, out)) return -1;
      o->max_stack = atoi(argv[++i]);
    } else if(!strcmp(a, "--off-cpu") || !strcmp(a, "--all-threads")) {
      o->off_cpu = 1;
    } else if(!strcmp(a, "--weighted")) {
      o->weighted = 1;
    } else if(!strcmp(a, "--per-thread")) {
      o->per_thread = 1;
    } else if(!strcmp(a, "-I") || !strcmp(a, "--interval-print")) {
      if(!need(i, argc, argv, out)) return -1;
      o->interval_ms = atoi(argv[++i]);
    } else if(!strcmp(a, "-n") || !strcmp(a, "--lines")) {
      if(!need(i, argc, argv, out)) return -1;
      o->top_n = atoi(argv[++i]);
    } else if(!strcmp(a, "--no-syms")) {
      o->no_syms = 1;
    } else if(!strcmp(a, "-s") || !strcmp(a, "--sort")) {
      if(!need(i, argc, argv, out)) return -1;
      snprintf(o->sort, sizeof o->sort, "%s", argv[++i]);
    } else if(!strcmp(a, "--children")) {
      o->children = 1;
    } else if(!strcmp(a, "-e") || !strcmp(a, "--event")) {
      /* only cpu-clock/task-clock style events exist; accept and ignore */
      if(!need(i, argc, argv, out)) return -1;
      i++;
    } else if(!strcmp(a, "--")) {
      continue;
    } else if(!strcmp(a, "sleep") && i + 1 < argc) {
      o->duration = atof(argv[++i]);    /* perf record -p X -- sleep 10 */
    } else {
      out_printf(out, "error: unknown option '%s' (try 'help')\n", a);
      return -1;
    }
  }

  if(o->freq < 1) o->freq = 1;
  if(o->freq > 2000) o->freq = 2000;
  if(o->max_stack < 1) o->max_stack = 1;
  if(o->max_stack > MAX_STACK) o->max_stack = MAX_STACK;
  if(o->top_n < 1) o->top_n = 1;
  return 0;
}

int
resolve_target(opts_t *o, out_t *out) {
  if(o->pid < 0 && o->comm[0]) {
    if(proc_find_by_name(o->comm, &o->pid)) {
      out_printf(out, "error: no process named '%s'\n", o->comm);
      return -1;
    }
  }
  if(o->pid < 0) {
    out_printf(out, "error: no target given, use -p <pid|name>\n");
    return -1;
  }
  if(!proc_exists(o->pid)) {
    out_printf(out, "error: no such process %d\n", o->pid);
    return -1;
  }
  return 0;
}
