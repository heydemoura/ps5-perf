/* ps5-perf payload: TCP front-end and command dispatch.
 *
 * Like linux/tools/perf/perf.c, sub-commands are looked up by name in a
 * table and invoked with (argc, argv). Instead of a terminal, every
 * connection on PS5PERF_PORT is a session: one command per line, output is
 * streamed back, and each command's output is terminated by a line
 *   #END rc=<n>
 * so tools can drive the protocol non-interactively. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <ps5/kernel.h>

#include "ps5perf.h"

struct cmd_struct {
  const char *cmd;
  int (*fn)(int, char **, out_t *);
};

static int cmd_quit(int argc, char **argv, out_t *o) { (void)argc; (void)argv; (void)o; return 0; }
static int cmd_shutdown(int argc, char **argv, out_t *o) { (void)argc; (void)argv; (void)o; return 0; }

static struct cmd_struct commands[] = {
  { "help",     cmd_help     },
  { "version",  cmd_version  },
  { "list",     cmd_list     },
  { "ps",       cmd_ps       },
  { "threads",  cmd_threads  },
  { "maps",     cmd_maps     },
  { "stat",     cmd_stat     },
  { "record",   cmd_record   },
  { "script",   cmd_script   },
  { "report",   cmd_report   },
  { "top",      cmd_top      },
  { "quit",     cmd_quit     },
  { "exit",     cmd_quit     },
  { "shutdown", cmd_shutdown },
};

volatile int g_shutdown = 0;
extern pthread_mutex_t g_sampler_lock;

static void
fatal_signal(int sig) {
  sampler_emergency_detach();
  klogf("fatal signal %d, target detached", sig);
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}
static int g_listen_fd = -1;

/* split a line into argv, honouring "double" and 'single' quotes */
static int
tokenize(char *line, char **argv, int max) {
  int argc = 0;
  char *p = line;

  while(*p && argc < max - 1) {
    while(*p == ' ' || *p == '\t') p++;
    if(!*p) break;
    char q = 0;
    if(*p == '"' || *p == '\'') q = *p++;
    argv[argc++] = p;
    char *w = p;
    while(*p && (q ? *p != q : (*p != ' ' && *p != '\t'))) *w++ = *p++;
    if(*p) p++;
    *w = 0;
  }
  argv[argc] = NULL;
  return argc;
}

static int
handle_line(char *line, out_t *o, int *quit) {
  char *args[64];
  char **argv = args;
  int argc;

  line[strcspn(line, "\r\n")] = 0;
  argc = tokenize(line, args, 64);
  if(!argc) return 1;

  /* allow an optional leading "perf" like the real tool: "perf top -p 1" */
  if(!strcmp(argv[0], "perf") && argc > 1) { argv++; argc--; }

  for(size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    if(strcmp(argv[0], commands[i].cmd)) continue;
    klogf("cmd: %s", argv[0]);
    if(commands[i].fn == cmd_quit) { *quit = 1; return 0; }
    if(commands[i].fn == cmd_shutdown) {
      out_printf(o, "ps5-perf shutting down\n#END rc=0\n");
      out_flush(o);
      g_shutdown = 1;
      *quit = 1;
      shutdown(g_listen_fd, SHUT_RDWR);
      close(g_listen_fd);
      return 0;
    }
    int rc = commands[i].fn(argc, argv, o);
    out_printf(o, "#END rc=%d\n", rc);
    out_flush(o);
    return 0;
  }
  out_printf(o, "ps5-perf: '%s' is not a ps5-perf command. See 'help'.\n#END rc=1\n", argv[0]);
  out_flush(o);
  return 0;
}

static void *
client_thread(void *arg) {
  int fd = (int)(intptr_t)arg;
  out_t *o = malloc(sizeof(out_t));
  char line[4096];
  size_t len = 0;
  int quit = 0;

  if(!o || out_init(o, fd)) { free(o); close(fd); return NULL; }
  uint32_t fw = kernel_get_fw_version();
  out_printf(o, "# ps5-perf %s on PS5 fw %x.%02x - type 'help' for commands\n#END rc=0\n",
             PS5PERF_VERSION, (fw >> 24) & 0xff, (fw >> 16) & 0xff);
  out_flush(o);

  while(!quit && !g_shutdown) {
    ssize_t n = recv(fd, line + len, sizeof(line) - 1 - len, 0);
    if(n <= 0) break;
    len += (size_t)n;
    line[len] = 0;
    char *nl;
    while(!quit && (nl = memchr(line, '\n', len))) {
      *nl = 0;
      handle_line(line, o, &quit);
      size_t used = (size_t)(nl - line) + 1;
      memmove(line, nl + 1, len - used);
      len -= used;
      line[len] = 0;
    }
    if(len == sizeof(line) - 1) len = 0;   /* overlong line: drop */
    if(o->err) break;
  }

  out_flush(o);
  close(fd);
  out_free(o);
  free(o);
  return NULL;
}

int
main(void) {
  struct sockaddr_in sa;
  int one = 1;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGSEGV, fatal_signal);
  signal(SIGBUS, fatal_signal);
  signal(SIGILL, fatal_signal);
  signal(SIGFPE, fatal_signal);
  signal(SIGABRT, fatal_signal);
  klogf("ps5-perf %s starting (pid %d)", PS5PERF_VERSION, getpid());

  if(pt_init()) {
    notify("ps5-perf: unable to obtain debugger privileges");
    return 1;
  }

  if((g_listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    klogf("socket: %s", strerror(errno));
    return 1;
  }
  setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(PS5PERF_PORT);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(g_listen_fd, (struct sockaddr *)&sa, sizeof sa) || listen(g_listen_fd, 8)) {
    klogf("bind/listen on port %d: %s", PS5PERF_PORT, strerror(errno));
    notify("ps5-perf: port %d busy (already running?)", PS5PERF_PORT);
    close(g_listen_fd);
    return 1;
  }

  kthreads_init();
  klogf("listening on port %d", PS5PERF_PORT);
  notify("ps5-perf %s listening on port %d", PS5PERF_VERSION, PS5PERF_PORT);

  while(!g_shutdown) {
    int fd = accept(g_listen_fd, NULL, NULL);
    if(fd < 0) {
      if(errno == EINTR) continue;
      if(g_shutdown) break;
      klogf("accept: %s", strerror(errno));
      sleep_ns(100000000ull);
      continue;
    }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, 1 << 20);
    if(pthread_create(&th, &at, client_thread, (void *)(intptr_t)fd)) close(fd);
    pthread_attr_destroy(&at);
  }

  klogf("shutting down");
  /* wait for a running sampling session to detach from its target */
  pthread_mutex_lock(&g_sampler_lock);
  sleep_ns(200000000ull);
  return 0;
}
