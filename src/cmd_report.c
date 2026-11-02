/* perf report / perf top: on-console aggregation of cpu-clock samples. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ps5perf.h"

extern pthread_mutex_t g_sampler_lock;

/* ------------------------------------------------------- hash table --- */

typedef struct agg agg_t;

typedef struct ent {
  char     *key;
  uint64_t  hash;
  uint64_t  self_w, self_n;
  uint64_t  child_w, child_n;
  agg_t    *chains;           /* callers of this entry (report -g) */
} ent_t;

struct agg {
  ent_t   *e;
  size_t   cap, n;
  uint64_t total_w, total_n;
};

#define AGG_MAX_ENTRIES 500000

static uint64_t
fnv(const char *s) {
  uint64_t h = 1469598103934665603ull;
  while(*s) { h ^= (unsigned char)*s++; h *= 1099511628211ull; }
  return h;
}

static void agg_free(agg_t *a);

static int
agg_grow(agg_t *a) {
  size_t ncap = a->cap ? a->cap * 2 : 1024;
  ent_t *ne = calloc(ncap, sizeof(ent_t));
  if(!ne) return -1;
  for(size_t i = 0; i < a->cap; i++) {
    if(!a->e[i].key) continue;
    size_t j = a->e[i].hash & (ncap - 1);
    while(ne[j].key) j = (j + 1) & (ncap - 1);
    ne[j] = a->e[i];
  }
  free(a->e);
  a->e = ne;
  a->cap = ncap;
  return 0;
}

static ent_t *
agg_get(agg_t *a, const char *key) {
  uint64_t h = fnv(key);

  if((a->n + 1) * 2 > a->cap && agg_grow(a)) return NULL;
  size_t j = h & (a->cap - 1);
  while(a->e[j].key) {
    if(a->e[j].hash == h && !strcmp(a->e[j].key, key)) return &a->e[j];
    j = (j + 1) & (a->cap - 1);
  }
  if(a->n >= AGG_MAX_ENTRIES) return NULL;
  a->e[j].key = strdup(key);
  if(!a->e[j].key) return NULL;
  a->e[j].hash = h;
  a->n++;
  return &a->e[j];
}

static void
agg_free(agg_t *a) {
  for(size_t i = 0; i < a->cap; i++) {
    free(a->e[i].key);
    if(a->e[i].chains) { agg_free(a->e[i].chains); free(a->e[i].chains); }
  }
  free(a->e);
  memset(a, 0, sizeof *a);
}

/* ----------------------------------------------------- aggregation ---- */

enum { K_COMM = 1, K_TID = 2, K_DSO = 4, K_SYM = 8 };

typedef struct rep_ctx {
  agg_t      agg;
  modlist_t *ml;
  int        keys;
  int        callgraph;
  int        children;
  uint64_t   fixed_weight;     /* off-cpu: every sample counts one period */
  /* top */
  out_t     *o;
  int        top;
  int        top_n;
  double     interval;
  double     last_print;
  double     last_t;
  pid_t      pid;
  const char *comm;
} rep_ctx_t;

static int
parse_sort(const char *s) {
  int k = 0;
  char buf[64];
  snprintf(buf, sizeof buf, "%s", s);
  char *save = NULL;
  for(char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
    if(!strcmp(tok, "comm")) k |= K_COMM;
    else if(!strcmp(tok, "tid") || !strcmp(tok, "pid")) k |= K_TID;
    else if(!strcmp(tok, "dso")) k |= K_DSO;
    else if(!strcmp(tok, "sym") || !strcmp(tok, "symbol")) k |= K_SYM;
  }
  return k ? k : (K_COMM | K_DSO | K_SYM);
}

static void
frame_name(const rep_ctx_t *c, uint64_t ip, int is_ret, char *sym, size_t symlen,
           const char **dso) {
  uint64_t off;
  symbolize(c->ml, is_ret ? ip - 1 : ip, sym, symlen, dso, &off);
  /* addresses outside any module: keep them distinct instead of
   * collapsing everything into one [unknown] bucket */
  if(!strcmp(sym, "[unknown]"))
    snprintf(sym, symlen, "0x%lx", (unsigned long)ip);
}

static void
make_key(const rep_ctx_t *c, const sample_t *s, const char *dso, const char *sym,
         char *key, size_t len) {
  int n = 0;
  key[0] = 0;
  if(c->keys & K_COMM) n += snprintf(key + n, len - n, "%s\x1f", s->tname);
  if(c->keys & K_TID)  n += snprintf(key + n, len - n, "%d\x1f", s->tid);
  if(c->keys & K_DSO)  n += snprintf(key + n, len - n, "%s\x1f", dso);
  if(c->keys & K_SYM)  n += snprintf(key + n, len - n, "%s\x1f", sym);
}

static void
rep_sample(void *vctx, const sample_t *s) {
  rep_ctx_t *c = vctx;
  uint64_t w = c->fixed_weight ? c->fixed_weight : s->weight_ns;
  char sym[160], key[400];
  const char *dso;

  if(!s->nips) return;
  c->agg.total_w += w;
  c->agg.total_n++;

  frame_name(c, s->ips[0], 0, sym, sizeof sym, &dso);
  make_key(c, s, dso, sym, key, sizeof key);
  ent_t *e = agg_get(&c->agg, key);
  if(!e) return;
  e->self_w += w;
  e->self_n++;

  if(c->callgraph && s->nips > 1 && !c->top) {
    char chain[1024];
    int n = 0;
    chain[0] = 0;
    for(int i = 1; i < s->nips && i <= 8 && n < (int)sizeof(chain) - 200; i++) {
      char fs[160];
      const char *fd;
      frame_name(c, s->ips[i], 1, fs, sizeof fs, &fd);
      n += snprintf(chain + n, sizeof(chain) - n, "%s%s", i > 1 ? "\x1f" : "", fs);
    }
    if(!e->chains) e->chains = calloc(1, sizeof(agg_t));
    if(e->chains) {
      ent_t *ce = agg_get(e->chains, chain);
      if(ce) { ce->self_w += w; ce->self_n++; }
    }
  }

  if(c->children) {
    uint64_t seen[MAX_STACK];
    int nseen = 0;
    for(int i = 0; i < s->nips; i++) {
      frame_name(c, s->ips[i], i > 0, sym, sizeof sym, &dso);
      make_key(c, s, dso, sym, key, sizeof key);
      uint64_t h = fnv(key);
      int dup = 0;
      for(int j = 0; j < nseen; j++) if(seen[j] == h) { dup = 1; break; }
      if(dup) continue;
      seen[nseen++] = h;
      ent_t *ce = agg_get(&c->agg, key);
      if(ce) { ce->child_w += w; ce->child_n++; }
    }
  }
}

static int
cmp_self(const void *a, const void *b) {
  const ent_t *x = *(const ent_t **)a, *y = *(const ent_t **)b;
  return x->self_w < y->self_w ? 1 : x->self_w > y->self_w ? -1 : 0;
}

static int
cmp_child(const void *a, const void *b) {
  const ent_t *x = *(const ent_t **)a, *y = *(const ent_t **)b;
  return x->child_w < y->child_w ? 1 : x->child_w > y->child_w ? -1 : 0;
}

static ent_t **
sorted(agg_t *a, int by_children, size_t *n) {
  ent_t **v = malloc(sizeof(ent_t *) * (a->n + 1));
  *n = 0;
  if(!v) return NULL;
  for(size_t i = 0; i < a->cap; i++)
    if(a->e[i].key && (by_children ? a->e[i].child_w : a->e[i].self_w)) v[(*n)++] = &a->e[i];
  qsort(v, *n, sizeof(ent_t *), by_children ? cmp_child : cmp_self);
  return v;
}

static void
split_key(const char *key, char fields[4][160]) {
  int f = 0, k = 0;
  for(int i = 0; i < 4; i++) fields[i][0] = 0;
  for(const char *p = key; *p && f < 4; p++) {
    if(*p == '\x1f') { fields[f][k] = 0; f++; k = 0; continue; }
    if(k < 159) fields[f][k++] = *p;
  }
}

static void
print_table(rep_ctx_t *c, out_t *o, int limit) {
  size_t n;
  ent_t **v = sorted(&c->agg, c->children, &n);
  const char *names[4];
  int nk = 0;
  int width[4] = { 0 };

  if(!v) return;
  if(c->keys & K_COMM) names[nk++] = "Command";
  if(c->keys & K_TID)  names[nk++] = "Tid";
  if(c->keys & K_DSO)  names[nk++] = "Shared Object";
  if(c->keys & K_SYM)  names[nk++] = "Symbol";

  for(int k = 0; k < nk; k++) width[k] = (int)strlen(names[k]);
  for(size_t i = 0; i < n && (int)i < limit; i++) {
    char f[4][160];
    split_key(v[i]->key, f);
    for(int k = 0; k < nk; k++) {
      int l = (int)strlen(f[k]);
      if(l > width[k]) width[k] = l > 48 ? 48 : l;
    }
  }

  out_printf(o, "#\n# %s%s  %7s", c->children ? "Children      Self" : "Overhead",
             "", "Samples");
  for(int k = 0; k < nk; k++) out_printf(o, "  %-*s", width[k], names[k]);
  out_printf(o, "\n# %s  .......", c->children ? "........  ........" : "........");
  for(int k = 0; k < nk; k++) {
    out_printf(o, "  ");
    for(int j = 0; j < width[k]; j++) out_write(o, ".", 1);
  }
  out_printf(o, "\n#\n");

  double tw = c->agg.total_w ? (double)c->agg.total_w : 1;
  for(size_t i = 0; i < n && (int)i < limit; i++) {
    char f[4][160];
    ent_t *e = v[i];
    split_key(e->key, f);
    if(c->children)
      out_printf(o, "  %7.2f%%  %7.2f%%  %7lu", 100.0 * e->child_w / tw, 100.0 * e->self_w / tw,
                 (unsigned long)e->child_n);
    else
      out_printf(o, "  %7.2f%%  %7lu", 100.0 * e->self_w / tw, (unsigned long)e->self_n);
    for(int k = 0; k < nk; k++) {
      int is_sym = !strcmp(names[k], "Symbol");
      out_printf(o, "  %s%-*.*s", is_sym ? "[.] " : "", width[k], 48, f[k]);
    }
    out_printf(o, "\n");

    if(e->chains && e->chains->n) {
      size_t cn;
      ent_t **cv = sorted(e->chains, 0, &cn);
      for(size_t j = 0; cv && j < cn && j < 3; j++) {
        out_printf(o, "            |--%5.2f%%-- ", 100.0 * cv[j]->self_w / (e->self_w ? e->self_w : 1));
        int first = 1;
        for(const char *p = cv[j]->key; *p;) {
          const char *q = strchr(p, '\x1f');
          size_t l = q ? (size_t)(q - p) : strlen(p);
          out_printf(o, "%s%.*s", first ? "" : "\n            |           <- ", (int)l, p);
          first = 0;
          p += l;
          if(*p) p++;
        }
        out_printf(o, "\n");
      }
      if(cv && cn) out_printf(o, "\n");
      free(cv);
    }
  }
  free(v);
}

/* ------------------------------------------------------------ top ----- */

static int
top_tick(void *vctx, double t) {
  rep_ctx_t *c = vctx;
  c->last_t = t;
  if(t - c->last_print < c->interval) return c->o->err != 0;

  out_printf(c->o, "\n=== ps5-perf top: pid %d (%s)  t=%.1fs  samples=%lu  cpu=%.2f CPUs ===\n",
             c->pid, c->comm, t, (unsigned long)c->agg.total_n,
             c->agg.total_w / 1e9 / (t - c->last_print));
  print_table(c, c->o, c->top_n);
  out_printf(c->o, "#END-FRAME\n");
  out_flush(c->o);
  agg_free(&c->agg);
  c->last_print = t;
  return c->o->err != 0;
}

/* --------------------------------------------------------- commands --- */

static int
run_profile(int argc, char **argv, out_t *o, int top) {
  opts_t op;
  modlist_t ml;
  rep_ctx_t c;
  sampler_cfg_t cfg;
  sampler_stats_t st;
  thread_info_t ti;
  char comm[64] = "";
  char err[256] = "";
  int rc;

  if(opts_parse(argc, argv, &op, o) || resolve_target(&op, o)) return -1;
  if(pthread_mutex_trylock(&g_sampler_lock)) {
    out_printf(o, "error: another sampling session is active\n");
    return -1;
  }
  proc_threads(op.pid, &ti, 1, comm, sizeof comm);
  if(modules_load(op.pid, &ml, 1, 0)) memset(&ml, 0, sizeof ml);

  memset(&c, 0, sizeof c);
  c.ml = &ml;
  c.keys = parse_sort(op.sort);
  c.callgraph = op.callgraph;
  c.children = op.children && op.callgraph;
  c.fixed_weight = op.off_cpu ? 1000000000ull / op.freq : 0;
  c.o = o;
  c.top = top;
  c.top_n = op.top_n;
  c.interval = op.interval_ms > 0 ? op.interval_ms / 1000.0 : 2.0;
  c.pid = op.pid;
  c.comm = comm;
  if(top && !op.sort[0]) c.keys = K_DSO | K_SYM;

  if(op.duration <= 0)
    out_printf(o, "# sampling pid %d (%s) at %d Hz, send a newline to stop\n", op.pid, comm,
               op.freq);
  else
    out_printf(o, "# sampling pid %d (%s) at %d Hz for %.1fs\n", op.pid, comm, op.freq,
               op.duration);
  out_flush(o);

  memset(&cfg, 0, sizeof cfg);
  cfg.pid = op.pid;
  cfg.tid = op.tid;
  cfg.freq = op.freq;
  cfg.duration = op.duration;
  cfg.callgraph = op.callgraph || op.children;
  cfg.max_stack = op.max_stack;
  cfg.off_cpu = op.off_cpu;
  cfg.weighted = op.weighted;
  cfg.client_fd = o->fd;
  cfg.mods = &ml;
  cfg.on_sample = rep_sample;
  cfg.on_tick = top ? top_tick : NULL;
  cfg.ctx = &c;

  rc = sampler_run(&cfg, &st, err, sizeof err);
  if(rc) {
    out_printf(o, "error: %s\n", err);
  } else if(!top) {
    out_printf(o, "# To display the perf.data header info, please use --header/--header-only options.\n#\n");
    out_printf(o, "# ps5-perf report: pid %d (%s)\n", op.pid, comm);
    out_printf(o, "# Samples: %lu  of event 'cpu-clock'  (sampling mode: %s)\n",
               (unsigned long)c.agg.total_n, sampler_mode_name(st.mode));
    out_printf(o, "# Event count (approx.): %lu ns  (%.2f CPUs over %.3fs)\n",
               (unsigned long)c.agg.total_w, c.agg.total_w / 1e9 / (st.elapsed > 0 ? st.elapsed : 1),
               st.elapsed);
    uint64_t nstops = st.rounds - st.no_stop_rounds;
    out_printf(o, "# Sampler: %lu ticks, %lu stops, target stopped avg %.1fus / max %.1fus "
               "(%.2f%% of wall time)%s\n", (unsigned long)st.rounds, (unsigned long)nstops,
               nstops ? st.stop_ns_total / 1e3 / nstops : 0.0, st.stop_ns_max / 1e3,
               st.elapsed > 0 ? 100.0 * st.stop_ns_total / 1e9 / st.elapsed : 0.0,
               st.exited ? ", target exited" : "");
    print_table(&c, o, op.top_n);
    out_printf(o, "\n");
  }

  agg_free(&c.agg);
  modules_free(&ml);
  pthread_mutex_unlock(&g_sampler_lock);
  return rc;
}

int
cmd_report(int argc, char **argv, out_t *o) {
  return run_profile(argc, argv, o, 0);
}

int
cmd_top(int argc, char **argv, out_t *o) {
  return run_profile(argc, argv, o, 1);
}
