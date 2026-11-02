/* Module map + function boundaries for a PS5 process.
 *
 * The module list comes from the kernel's per-process dynlib object list
 * (struct proc + 0x3e8, the same walk the SDK's kernel_dynlib_* helpers
 * use). Each object gives us map base, text size, the dynamic symbol table
 * (exported symbols, named by NID for Sony modules) and the address of
 * .eh_frame_hdr, whose binary search table lists the start address of every
 * function with unwind info - which is practically every function, even in
 * stripped game executables. */
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <ps5/kernel.h>

#include "ps5perf.h"

typedef struct dynlib_dynsec {
  struct { unsigned long le_next, le_prev; } list_entry;
  unsigned long sysvec;
  unsigned int  refcount;
  unsigned long size;
  unsigned long symtab;
  unsigned long symtabsize;
  unsigned long strtab;
  unsigned long strtabsize;
  unsigned long pltrela, pltrelasize;
  unsigned long rela, relasize;
  unsigned long hash, hashsize;
  unsigned long dynamic, dynamicsize;
  unsigned long sce_comment, sce_commentsize;
  unsigned long sce_dynlib, sce_dynlibsize;
  unsigned long unknown1, unknown1size;
  unsigned long buckets, bucketssize;
  unsigned int  nbuckets;
  unsigned long chains, chainssize;
  unsigned int  nchains;
  unsigned long unknown2[7];
} dynlib_dynsec_t;

typedef struct dynlib_obj {
  unsigned long next;
  unsigned long path;
  unsigned long unknown0[2];
  unsigned int  refcount;
  unsigned long handle;
  unsigned long mapbase;
  unsigned long mapsize;
  unsigned long textsize;
  unsigned long database;
  unsigned long datasize;
  unsigned long unknown1;
  unsigned long unknown1size;
  unsigned long entry;
  unsigned long unknown2;
  unsigned long vaddrbase;
  unsigned int  tlsindex;
  unsigned long tlsinit;
  unsigned long tlsinitsize;
  unsigned long tlssize;
  unsigned long tlsoffset;
  unsigned long tlsalign;
  unsigned long pltgot;
  unsigned long unknown3[6];
  unsigned long init;
  unsigned long fini;
  unsigned long eh_frame_hdr;
  unsigned long eh_frame_hdr_size;
  unsigned long eh_frame;
  unsigned long eh_frame_size;
  int status;
  int flags;
  unsigned long unknown4[5];
  unsigned long dynsec;
  unsigned long unknown5[6];
} dynlib_obj_t;

#define PROC_DYNLIB_OFFSET 0x3e8
#define MAX_MODULES        512

/* read target memory: ptrace if we are attached, else via kernel r/w */
static int
target_read(pid_t pid, int attached, uint64_t addr, void *buf, size_t len) {
  if(attached) return pt_read(pid, addr, buf, len);
  return kernel_proc_copyout(pid, (intptr_t)addr, buf, len) < 0 ? -1 : 0;
}

/* ------------------------------------------------- .eh_frame_hdr ------ */

#define DW_EH_PE_omit    0xff
#define DW_EH_PE_absptr  0x00
#define DW_EH_PE_udata4  0x03
#define DW_EH_PE_udata8  0x04
#define DW_EH_PE_sdata4  0x0b
#define DW_EH_PE_sdata8  0x0c
#define DW_EH_PE_pcrel   0x10
#define DW_EH_PE_datarel 0x30

static int
enc_size(uint8_t enc) {
  switch(enc & 0x0f) {
  case DW_EH_PE_absptr: return 8;
  case DW_EH_PE_udata4: case DW_EH_PE_sdata4: return 4;
  case DW_EH_PE_udata8: case DW_EH_PE_sdata8: return 8;
  default: return -1;
  }
}

static int64_t
enc_read(const uint8_t *p, uint8_t enc) {
  switch(enc & 0x0f) {
  case DW_EH_PE_udata4: return *(const uint32_t *)p;
  case DW_EH_PE_sdata4: return *(const int32_t *)p;
  default:              return *(const int64_t *)p;
  }
}

static int
cmp_func(const void *a, const void *b) {
  const func_t *x = a, *y = b;
  if(x->start != y->start) return x->start < y->start ? -1 : 1;
  /* named entries first so dedup keeps them */
  return (y->name >= 0) - (x->name >= 0);
}

static int
add_func(module_t *m, int *cap, uint64_t start, uint32_t size, int32_t name) {
  if(m->nfuncs == *cap) {
    int ncap = *cap ? *cap * 2 : 1024;
    func_t *nf = realloc(m->funcs, sizeof(func_t) * ncap);
    if(!nf) return -1;
    m->funcs = nf;
    *cap = ncap;
  }
  m->funcs[m->nfuncs++] = (func_t){ start, size, name };
  return 0;
}

static int32_t
pool_add(module_t *m, size_t *cap, const char *s, size_t len) {
  if(m->strpool_len + len + 1 > *cap) {
    size_t ncap = *cap ? *cap * 2 : 16384;
    while(ncap < m->strpool_len + len + 1) ncap *= 2;
    char *np = realloc(m->strpool, ncap);
    if(!np) return -1;
    m->strpool = np;
    *cap = ncap;
  }
  int32_t off = (int32_t)m->strpool_len;
  memcpy(m->strpool + off, s, len);
  m->strpool[off + len] = 0;
  m->strpool_len += len + 1;
  return off;
}

static void
load_eh_frame_hdr(pid_t pid, int attached, module_t *m, int *cap,
                  uint64_t hdr, uint64_t hdr_size) {
  uint8_t h[4 + 8 + 8];
  uint64_t text_size = m->text_end - m->base;

  if(!hdr) return;
  if(hdr < m->base) hdr += m->base;               /* relative address */
  if(hdr >= m->map_end) return;
  if(target_read(pid, attached, hdr, h, sizeof h)) return;
  if(h[0] != 1) return;

  uint8_t ptr_enc = h[1], cnt_enc = h[2], tab_enc = h[3];
  int ps = enc_size(ptr_enc), cs = enc_size(cnt_enc);
  if(ptr_enc == DW_EH_PE_omit || cnt_enc == DW_EH_PE_omit || ps < 0 || cs < 0) return;
  if(tab_enc != (DW_EH_PE_datarel | DW_EH_PE_sdata4)) return;

  uint64_t count = (uint64_t)enc_read(h + 4 + ps, cnt_enc);
  uint64_t tab = hdr + 4 + ps + cs;
  if(count == 0 || count > 4000000) return;
  if(hdr_size && 4 + ps + cs + count * 8 > hdr_size + 16) return;

  size_t bytes = count * 8;
  int32_t *t = malloc(bytes);
  if(!t) return;
  /* read in chunks, PT_IO is happiest with moderate sizes */
  for(size_t off = 0; off < bytes; off += 65536) {
    size_t n = bytes - off < 65536 ? bytes - off : 65536;
    if(target_read(pid, attached, tab + off, (char *)t + off, n)) { free(t); return; }
  }

  for(uint64_t i = 0; i < count; i++) {
    int64_t loc = (int64_t)hdr + t[i * 2];
    if(loc < (int64_t)m->base) continue;
    uint64_t rel = (uint64_t)loc - m->base;
    if(rel >= text_size) continue;
    add_func(m, cap, rel, 0, -1);
    m->n_eh++;
  }
  free(t);
}

static void
load_dynsym(module_t *m, int *cap, size_t *pcap, uint64_t dynsec_addr) {
  dynlib_dynsec_t ds;

  if(!dynsec_addr) return;
  if(kernel_copyout(dynsec_addr, &ds, sizeof ds) < 0) return;
  if(!ds.symtab || !ds.strtab) return;
  if(ds.symtabsize > (64u << 20) || ds.strtabsize > (64u << 20)) return;

  Elf64_Sym *syms = malloc(ds.symtabsize);
  char *str = malloc(ds.strtabsize + 1);
  if(!syms || !str) goto out;
  if(kernel_copyout(ds.symtab, syms, ds.symtabsize) < 0) goto out;
  if(kernel_copyout(ds.strtab, str, ds.strtabsize) < 0) goto out;
  str[ds.strtabsize] = 0;

  for(size_t i = 0; i < ds.symtabsize / sizeof(Elf64_Sym); i++) {
    Elf64_Sym *s = &syms[i];
    if(ELF64_ST_TYPE(s->st_info) != STT_FUNC) continue;
    if(!s->st_value || s->st_shndx == SHN_UNDEF) continue;
    if(s->st_value >= m->text_end - m->base) continue;
    if(s->st_name >= ds.strtabsize) continue;
    const char *nm = str + s->st_name;
    size_t len = strcspn(nm, "#");          /* "NID#lib#mod" -> "NID" */
    if(!len) continue;
    int32_t off = pool_add(m, pcap, nm, len);
    if(off < 0) break;
    add_func(m, cap, s->st_value, (uint32_t)s->st_size, off);
    m->n_dynsym++;
  }
out:
  free(syms);
  free(str);
}

static void
finish_funcs(module_t *m) {
  if(!m->nfuncs) return;
  qsort(m->funcs, m->nfuncs, sizeof(func_t), cmp_func);

  int w = 0;
  for(int r = 0; r < m->nfuncs; r++) {
    if(w && m->funcs[w - 1].start == m->funcs[r].start) {
      if(m->funcs[w - 1].name < 0) m->funcs[w - 1].name = m->funcs[r].name;
      if(!m->funcs[w - 1].size) m->funcs[w - 1].size = m->funcs[r].size;
      continue;
    }
    m->funcs[w++] = m->funcs[r];
  }
  m->nfuncs = w;

  uint64_t text_size = m->text_end - m->base;
  for(int i = 0; i < m->nfuncs; i++) {
    uint64_t lim = (i + 1 < m->nfuncs ? m->funcs[i + 1].start : text_size) - m->funcs[i].start;
    if(!m->funcs[i].size || m->funcs[i].size > lim) m->funcs[i].size = (uint32_t)lim;
  }
}

static int
cmp_mod(const void *a, const void *b) {
  const module_t *x = a, *y = b;
  return x->base < y->base ? -1 : x->base > y->base;
}

static int
load_from_vm_entries(pid_t pid, modlist_t *ml) {
  struct ptrace_vm_entry ve;
  char path[256];

  memset(&ve, 0, sizeof ve);
  ml->mods = calloc(MAX_MODULES, sizeof(module_t));
  if(!ml->mods) return -1;
  while(ml->n < MAX_MODULES) {
    ve.pve_path = path;
    ve.pve_pathlen = sizeof path;
    path[0] = 0;
    if(pt_call(PT_VM_ENTRY, pid, &ve, 0) < 0) break;
    if(!(ve.pve_prot & 4)) continue;     /* executable mappings only */
    module_t *m = &ml->mods[ml->n++];
    m->base = ve.pve_start;
    m->text_end = m->map_end = ve.pve_end + 1;
    snprintf(m->name, sizeof m->name, "[anon:%lx]", (unsigned long)ve.pve_start);
    snprintf(m->path, sizeof m->path, "%s", path);
  }
  return ml->n ? 0 : -1;
}

/* Executable mappings that are not backed by a kernel dynlib object, e.g.
 * code loaded by elfldr (payloads), JIT code, or the signal trampoline.
 * Read via sysctl(KERN_PROC_VMMAP), no ptrace needed. The lowest such region
 * of a process whose name is not a module (payload.elf) is named after the
 * process so host-side symbolization can match it to its ELF. */
static void
add_anon_exec(pid_t pid, modlist_t *ml) {
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid };
  size_t len = 0;
  char comm[64] = "";
  thread_info_t tot;
  int named = 0;

  if(proc_totals(pid, &tot, comm, sizeof comm) == 0) {
    for(int i = 0; i < ml->n; i++)
      if(!strcmp(ml->mods[i].name, comm)) named = 1;    /* e.g. eboot.bin */
  }
  if(sysctl(mib, 4, NULL, &len, NULL, 0) || !len) return;
  len += len / 2;
  char *buf = malloc(len);
  if(!buf) return;
  if(sysctl(mib, 4, buf, &len, NULL, 0)) { free(buf); return; }

  for(char *p = buf; p < buf + len && ml->n < MAX_MODULES;) {
    struct kinfo_vmentry *k = (struct kinfo_vmentry *)p;
    if(k->kve_structsize <= 0) break;
    p += k->kve_structsize;
    if(!(k->kve_protection & KVME_PROT_EXEC)) continue;
    if(module_find(ml, k->kve_start)) continue;

    module_t *m = &ml->mods[ml->n++];
    memset(m, 0, sizeof *m);
    m->base = k->kve_start;
    m->text_end = m->map_end = k->kve_end;
    if(!named && comm[0]) {
      snprintf(m->name, sizeof m->name, "%s", comm);
      named = 1;
    } else {
      snprintf(m->name, sizeof m->name, "[anon:%lx]", (unsigned long)k->kve_start);
    }
    snprintf(m->path, sizeof m->path, "[anon]");
    /* keep sorted for module_find() */
    qsort(ml->mods, ml->n, sizeof(module_t), cmp_mod);
  }
  free(buf);
}

int
modules_load(pid_t pid, modlist_t *ml, int with_funcs, int attached) {
  intptr_t kproc = kernel_get_proc(pid);
  uint64_t kaddr = 0;

  memset(ml, 0, sizeof *ml);
  if(!kproc || kernel_copyout(kproc + PROC_DYNLIB_OFFSET, &kaddr, sizeof kaddr) < 0 || !kaddr)
    return attached ? load_from_vm_entries(pid, ml) : -1;

  ml->mods = calloc(MAX_MODULES, sizeof(module_t));
  if(!ml->mods) return -1;

  for(int guard = 0; guard < MAX_MODULES; guard++) {
    dynlib_obj_t obj;

    if(kernel_copyout(kaddr, &kaddr, sizeof kaddr) < 0 || !kaddr) break;
    if(kernel_copyout(kaddr, &obj, sizeof obj) < 0) break;
    if(!obj.mapbase || !obj.mapsize) continue;

    module_t *m = &ml->mods[ml->n++];
    m->base = obj.mapbase;
    m->map_end = obj.mapbase + obj.mapsize;
    m->text_end = obj.mapbase + (obj.textsize && obj.textsize <= obj.mapsize ? obj.textsize : obj.mapsize);
    m->path[0] = 0;
    if(obj.path) kernel_copyout(obj.path, m->path, sizeof(m->path) - 1);
    m->path[sizeof(m->path) - 1] = 0;
    const char *bn = strrchr(m->path, '/');
    snprintf(m->name, sizeof m->name, "%s", bn ? bn + 1 : (m->path[0] ? m->path : "[unknown]"));

    if(with_funcs) {
      int cap = 0;
      size_t pcap = 0;
      load_dynsym(m, &cap, &pcap, obj.dynsec);
      load_eh_frame_hdr(pid, attached, m, &cap, obj.eh_frame_hdr, obj.eh_frame_hdr_size);
      finish_funcs(m);
    }
  }

  if(!ml->n) {
    free(ml->mods);
    ml->mods = NULL;
    return attached ? load_from_vm_entries(pid, ml) : -1;
  }
  qsort(ml->mods, ml->n, sizeof(module_t), cmp_mod);
  add_anon_exec(pid, ml);
  return 0;
}

void
modules_free(modlist_t *ml) {
  for(int i = 0; i < ml->n; i++) {
    free(ml->mods[i].funcs);
    free(ml->mods[i].strpool);
  }
  free(ml->mods);
  memset(ml, 0, sizeof *ml);
}

const module_t *
module_find(const modlist_t *ml, uint64_t addr) {
  int lo = 0, hi = ml->n - 1;

  while(lo <= hi) {
    int mid = (lo + hi) / 2;
    const module_t *m = &ml->mods[mid];
    if(addr < m->base) hi = mid - 1;
    else if(addr >= m->map_end) lo = mid + 1;
    else return m;
  }
  return NULL;
}

const func_t *
func_find(const module_t *m, uint64_t addr) {
  uint64_t rel = addr - m->base;
  int lo = 0, hi = m->nfuncs - 1, best = -1;

  while(lo <= hi) {
    int mid = (lo + hi) / 2;
    if(m->funcs[mid].start <= rel) { best = mid; lo = mid + 1; }
    else hi = mid - 1;
  }
  if(best < 0) return NULL;
  const func_t *f = &m->funcs[best];
  if(rel - f->start >= f->size) return NULL;
  return f;
}

const char *
func_name(const module_t *m, const func_t *f, char *buf, size_t len) {
  if(f->name >= 0) {
    const char *n = m->strpool + f->name;
    const char *real = strlen(n) == 11 ? nid_lookup(n) : NULL;
    return real ? real : n;
  }
  snprintf(buf, len, "sub_%lx", (unsigned long)f->start);
  return buf;
}

void
symbolize(const modlist_t *ml, uint64_t addr, char *sym, size_t symlen,
          const char **dso, uint64_t *symoff) {
  const module_t *m = ml ? module_find(ml, addr) : NULL;
  char tmp[32];

  *symoff = 0;
  if(!m) {
    *dso = "[unknown]";
    snprintf(sym, symlen, "[unknown]");
    return;
  }
  *dso = m->name;
  const func_t *f = func_find(m, addr);
  if(f) {
    snprintf(sym, symlen, "%s", func_name(m, f, tmp, sizeof tmp));
    *symoff = addr - m->base - f->start;
  } else {
    snprintf(sym, symlen, "%s+0x%lx", m->name, (unsigned long)(addr - m->base));
  }
}
