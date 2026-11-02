// shadow.c - shadow probes: capture the entry state of chosen exe functions in the running game (hybrid/shadow/README.md).
//
// Linked with ../loader/dinput8.c into a separate dinput8.dll (hybrid/shadow/build.sh); the entry point ShadowMain runs
// the loader's DllMain first, so every loader option (mode, time_scale, input_script, window_park, frame_dump) works
// as usual. Use it with mode=none: the probes need the original code at the function starts.
//
// At start each address in shadow_list gets an int3 at its first byte, and a vectored exception handler (first in the
// chain) catches the breakpoints. On a hit the handler puts the original byte back (the probe is disarmed), and for the
// first shadow_k hits of a function it captures the call:
//   1. waits for a free slot on the collector's semaphore (each live clone holds copy-on-write pages),
//   2. PssCaptureSnapshot(PSS_CAPTURE_VA_CLONE): a copy-on-write clone of the whole process at this instant,
//   3. duplicates the clone's process handle into the collector process and frees the snapshot (the clone lives on
//      while the collector holds its handle),
//   4. writes one fixed-size message to the collector's pipe: the function, thread, TEB, the game's clock values and
//      the x86 CONTEXT at the function's first instruction.
// Then the thread continues into the function. A function that still wants samples is armed again shadow_every ms
// later by a background thread, so samples spread over the run and a hot function costs nothing between them.
//
// hooks.ini keys ([hybrid], each with an FF_HYBRID_<KEY> environment override):
//   shadow_list   file next to the exe: hex addresses ('#' or ';' comments)       (no list: shadow off)
//   shadow_k      samples per function (1)          shadow_every  game-clock ms between two samples of one function
//                                                   (2000; the exe's QueryPerformanceCounter, so time_scale and
//                                                   fixed_step apply and capture stalls do not count)
//   shadow_max    samples in all (100000)           shadow_wait   ms to wait for a free clone slot (60000)
//   shadow_pipe   collector pipe (\\.\pipe\ff_shadow)  shadow_sem  collector semaphore (Local\ff_shadow_slots)
// Log: ff_shadow.log next to the exe; ff_shadow_hits.tsv (rewritten every 5 s) lists the probes that fired: address,
// breakpoint hits, samples taken.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HMODULE;
typedef u32 DWORD;

#define WINAPI __stdcall
#define IMPORT __declspec(dllimport)
#define NULL ((void *)0)
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)

IMPORT void *WINAPI VirtualAlloc(void *, u32, DWORD, DWORD);
IMPORT BOOL WINAPI VirtualProtect(void *, u32, DWORD, DWORD *);
IMPORT BOOL WINAPI FlushInstructionCache(HANDLE, const void *, u32);
IMPORT HANDLE WINAPI GetCurrentProcess(void);
IMPORT DWORD WINAPI GetCurrentProcessId(void);
IMPORT DWORD WINAPI GetCurrentThreadId(void);
IMPORT HANDLE WINAPI CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
IMPORT BOOL WINAPI ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
IMPORT BOOL WINAPI WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
IMPORT DWORD WINAPI GetFileSize(HANDLE, DWORD *);
IMPORT DWORD WINAPI SetFilePointer(HANDLE, long, long *, DWORD);
IMPORT BOOL WINAPI CloseHandle(HANDLE);
IMPORT DWORD WINAPI GetModuleFileNameA(HMODULE, char *, DWORD);
IMPORT HMODULE WINAPI GetModuleHandleA(const char *);
IMPORT DWORD WINAPI GetEnvironmentVariableA(const char *, char *, DWORD);
IMPORT DWORD WINAPI GetPrivateProfileStringA(const char *, const char *, const char *, char *, DWORD, const char *);
IMPORT DWORD WINAPI GetLastError(void);
IMPORT void *WINAPI AddVectoredExceptionHandler(u32, void *);
IMPORT HANDLE WINAPI CreateThread(void *, u32, void *, void *, DWORD, DWORD *);
IMPORT void WINAPI Sleep(DWORD);
IMPORT DWORD WINAPI GetTickCount(void);
IMPORT BOOL WINAPI QueryPerformanceCounter(u64 *);
IMPORT BOOL WINAPI QueryPerformanceFrequency(u64 *);
IMPORT void WINAPI GetSystemTimeAsFileTime(u64 *);
IMPORT HANDLE WINAPI OpenProcess(DWORD, BOOL, DWORD);
IMPORT HANDLE WINAPI OpenSemaphoreA(DWORD, BOOL, const char *);
IMPORT BOOL WINAPI ReleaseSemaphore(HANDLE, long, long *);
IMPORT DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
IMPORT BOOL WINAPI DuplicateHandle(HANDLE, HANDLE, HANDLE, HANDLE *, DWORD, BOOL, DWORD);
IMPORT BOOL WINAPI GetNamedPipeServerProcessId(HANDLE, DWORD *);
IMPORT DWORD WINAPI PssCaptureSnapshot(HANDLE, DWORD, DWORD, void **);
IMPORT DWORD WINAPI PssQuerySnapshot(void *, DWORD, void *, DWORD);
IMPORT DWORD WINAPI PssFreeSnapshot(HANDLE, void *);
IMPORT BOOL WINAPI MoveFileExA(const char *, const char *, DWORD);

BOOL WINAPI DllMain(HMODULE self, DWORD reason, void *reserved);  // the loader's, in dinput8.c

#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1
#define OPEN_EXISTING 3
#define CREATE_ALWAYS 2
#define FILE_END 2
#define PAGE_EXECUTE_READWRITE 0x40
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_READWRITE 0x04
#define PROCESS_DUP_HANDLE 0x40
#define SYNCHRONIZE 0x00100000u
#define SEMAPHORE_MODIFY_STATE 0x2
#define DUPLICATE_SAME_ACCESS 0x2
#define PSS_CAPTURE_VA_CLONE 0x1
#define PSS_QUERY_VA_CLONE_INFORMATION 1
#define EXCEPTION_BREAKPOINT 0x80000003u
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#define EXCEPTION_CONTINUE_SEARCH 0
#define CTX_SIZE 716
#define CTX_EIP 0xb8
#define MSG_MAGIC 0x4d534646u  // 'FFSM'
#define MAXPROBES 0x8000

typedef struct {
  u32 addr;
  u8 orig, armed, pad[2];
  volatile long hits, taken;
  volatile u32 pending;  // the rearm thread puts the int3 back once the game clock reaches rearm_at
  u64 rearm_at;          // in ticks of the game's own QueryPerformanceCounter (time_scale or fixed_step clock)
} Probe;

// The collector (hybrid/shadow/collector.py) reads exactly this layout.
typedef struct {
  u32 magic, size, seq, fn, tid, k, teb, pid, clone, tick, clock, stack_limit;  // stack_limit: TEB StackLimit when the probe fired, before the capture used more stack
  u64 qpc, qpf, ft;
  u8 context[CTX_SIZE], tail[4];  // 792 bytes, a multiple of 8 either way
} Msg;

static Probe *g_probes;
static u32 g_nprobes, g_k = 1, g_every = 2000, g_max = 100000, g_wait = 60000;
static u8 *g_text_lo, *g_text_hi;
static HANDLE g_pipe = INVALID_HANDLE_VALUE, g_collector, g_sem, g_log = INVALID_HANDLE_VALUE;
static volatile long g_seq, g_lock, g_loglock, g_skipped, g_failed;
static char g_dir[520], g_ini[600];
static BOOL(WINAPI *g_qpc)(u64 *);
static long(__cdecl *g_clock)(void);
static u32 g_tpm = 10000;  // QueryPerformanceCounter ticks per ms

// The game's clock: its own QueryPerformanceCounter import, which the loader scales (time_scale) or replaces with the
// frame clock (fixed_step). shadow_every counts in it, so samples spread over game time, not over capture stalls.
static u64 game_ticks(void) {
  u64 t = 0;
  if (!(g_qpc && g_qpc(&t))) QueryPerformanceCounter(&t);
  return t;
}

// ---------------------------------------------------------------- small helpers (no CRT)
static u32 slen(const char *s) {
  u32 n = 0;
  while (s[n]) n++;
  return n;
}
static char *scpy(char *d, const char *s) {
  while ((*d = *s++)) d++;
  return d;
}
static char *shex(char *d, u32 v) {
  *d++ = '0', *d++ = 'x';
  for (int i = 28; i >= 0; i -= 4) *d++ = "0123456789abcdef"[(v >> i) & 15];
  *d = 0;
  return d;
}
static char *sdec(char *d, u32 v) {
  char t[12], *p = t + 11;
  *p = 0;
  do *--p = (char)('0' + v % 10);
  while (v /= 10);
  return scpy(d, p);
}
static u32 pdec(const char *s, u32 def) {
  if (*s < '0' || *s > '9') return def;
  u32 v = 0;
  for (; *s >= '0' && *s <= '9'; s++) v = v * 10 + (u32)(*s - '0');
  return v;
}
static void spin(volatile long *l) {
  while (__sync_lock_test_and_set(l, 1)) Sleep(0);
}
static void unspin(volatile long *l) { __sync_lock_release(l); }

static void slog(const char *a, u32 v, int hex) {
  if (g_log == INVALID_HANDLE_VALUE) return;
  char line[400], *p = scpy(line, "shadow: ");
  u32 n = slen(a);
  if (n > 300) n = 300;
  for (u32 i = 0; i < n; i++) *p++ = a[i];
  *p = 0;
  if (hex == 1) p = shex(p, v);
  else if (hex == 0) p = sdec(p, v);
  p = scpy(p, "\r\n");
  DWORD w;
  spin(&g_loglock);
  WriteFile(g_log, line, (DWORD)(p - line), &w, NULL);
  unspin(&g_loglock);
}

static void cfg(const char *key, const char *envkey, const char *def, char *out, u32 cap) {
  DWORD n = GetEnvironmentVariableA(envkey, out, cap);
  if (n && n < cap) return;
  GetPrivateProfileStringA("hybrid", key, def, out, cap, g_ini);
}

// IAT slot of an import, by name (first match): the game's own clocks go through these (time_scale wraps them)
static void *iat_fn(u8 *exe, const char *name) {
  u8 *nt = exe + *(u32 *)(exe + 0x3c);
  u32 rva = *(u32 *)(nt + 0x80);
  if (!rva) return NULL;
  for (u32 *d = (u32 *)(exe + rva); d[3]; d += 5) {
    u32 *names = (u32 *)(exe + (d[0] ? d[0] : d[4])), *slots = (u32 *)(exe + d[4]);
    for (u32 i = 0; names[i]; i++) {
      if (names[i] & 0x80000000u) continue;
      const char *n = (const char *)(exe + names[i] + 2), *q = name;
      while (*n && *n == *q) n++, q++;
      if (!*n && !*q) return (void *)slots[i];
    }
  }
  return NULL;
}

// ---------------------------------------------------------------- probes
static Probe *find(u32 a) {  // g_probes is sorted by address
  u32 lo = 0, hi = g_nprobes;
  while (lo < hi) {
    u32 m = (lo + hi) / 2;
    if (g_probes[m].addr < a) lo = m + 1;
    else hi = m;
  }
  return lo < g_nprobes && g_probes[lo].addr == a ? &g_probes[lo] : NULL;
}

static void put(Probe *p, u8 b) {
  *(volatile u8 *)p->addr = b;
  FlushInstructionCache(GetCurrentProcess(), (void *)p->addr, 1);
}

static void capture(Probe *p, u32 *ctx, u32 stack_limit) {
  spin(&g_lock);
  if (WaitForSingleObject(g_sem, g_wait) != 0) {
    __sync_fetch_and_add(&g_skipped, 1);
    unspin(&g_lock);
    return;
  }
  static Msg m;
  u32 t0 = GetTickCount();
  void *snap = NULL;
  HANDLE clone = NULL, dup = NULL;
  DWORD rc = PssCaptureSnapshot(GetCurrentProcess(), PSS_CAPTURE_VA_CLONE, 0, &snap);
  if (!rc) rc = PssQuerySnapshot(snap, PSS_QUERY_VA_CLONE_INFORMATION, &clone, sizeof clone);
  if (!rc && !DuplicateHandle(GetCurrentProcess(), clone, g_collector, &dup, 0, 0, DUPLICATE_SAME_ACCESS))
    rc = GetLastError();
  if (snap) PssFreeSnapshot(GetCurrentProcess(), snap);
  if (rc) {
    ReleaseSemaphore(g_sem, 1, NULL);
    if (__sync_fetch_and_add(&g_failed, 1) < 8) slog("capture failed, error ", rc, 1);
    unspin(&g_lock);
    return;
  }
  m.magic = MSG_MAGIC;
  m.size = sizeof m;
  m.seq = (u32)__sync_fetch_and_add(&g_seq, 1);
  m.fn = p->addr;
  m.tid = GetCurrentThreadId();
  m.k = (u32)p->taken;
  u32 teb;
  __asm__ volatile("movl %%fs:0x18, %0" : "=r"(teb));
  m.teb = teb;
  m.stack_limit = stack_limit;
  m.pid = GetCurrentProcessId();
  m.clone = (u32)dup;
  m.tick = GetTickCount();
  m.clock = g_clock ? (u32)g_clock() : 0;
  if (!(g_qpc && g_qpc(&m.qpc))) QueryPerformanceCounter(&m.qpc);
  QueryPerformanceFrequency(&m.qpf);
  GetSystemTimeAsFileTime(&m.ft);
  u8 *c = (u8 *)ctx;
  for (u32 i = 0; i < CTX_SIZE; i++) m.context[i] = c[i];
  DWORD w = 0;
  if (!WriteFile(g_pipe, &m, sizeof m, &w, NULL) || w != sizeof m) {
    slog("pipe write failed (collector gone?), error ", GetLastError(), 1);
    CloseHandle(g_pipe);
    g_pipe = INVALID_HANDLE_VALUE;
  }
  if (m.seq < 32 || m.seq % 100 == 0) {
    char t[120], *q = scpy(t, "sample ");
    q = sdec(q, m.seq);
    q = scpy(q, " fn ");
    q = shex(q, m.fn);
    q = scpy(q, " call ");
    q = sdec(q, m.k);
    scpy(q, " ms ");
    slog(t, GetTickCount() - t0, 0);
  }
  unspin(&g_lock);
}

static void write_hits(void) {
  static char path[600], tmp[620], line[48];
  static volatile long busy;
  if (__sync_lock_test_and_set(&busy, 1)) return;
  scpy(scpy(path, g_dir), "ff_shadow_hits.tsv");
  scpy(scpy(tmp, path), ".tmp");
  HANDLE h = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0x80, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    DWORD w;
    WriteFile(h, "addr\thits\ttaken\r\n", 17, &w, NULL);
    for (u32 i = 0; i < g_nprobes; i++) {
      Probe *p = &g_probes[i];
      if (!p->hits) continue;
      char *q = shex(line, p->addr);
      q = sdec(scpy(q, "\t"), (u32)p->hits);
      q = scpy(sdec(scpy(q, "\t"), (u32)p->taken), "\r\n");
      WriteFile(h, line, (DWORD)(q - line), &w, NULL);
    }
    CloseHandle(h);
    MoveFileExA(tmp, path, 1);  // MOVEFILE_REPLACE_EXISTING
  }
  __sync_lock_release(&busy);
}

static long WINAPI shadow_veh(u32 **ep) {
  u32 *rec = ep[0], *ctx = ep[1], stack_limit;
  if (rec[0] != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
  __asm__ volatile("movl %%fs:0x8, %0" : "=r"(stack_limit));
  Probe *p = find(rec[3]);  // ExceptionAddress: the int3 itself
  if (!p) return EXCEPTION_CONTINUE_SEARCH;
  if (*(u8 *)p->addr == 0xCC) put(p, p->orig);
  p->armed = 0;
  ctx[CTX_EIP / 4] = p->addr;  // the context the probe saw: EIP at the function start
  __sync_fetch_and_add(&p->hits, 1);
  if (g_pipe != INVALID_HANDLE_VALUE && (u32)p->taken < g_k && (u32)g_seq < g_max) {
    __sync_fetch_and_add(&p->taken, 1);
    capture(p, ctx, stack_limit);
  }
  if ((u32)p->taken < g_k && (u32)g_seq < g_max) {
    p->rearm_at = game_ticks() + (u64)g_every * g_tpm;
    p->pending = 1;
  }
  return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI rearm_thread(void *x) {
  (void)x;
  for (u32 tick = 1;; tick++) {
    Sleep(50);
    if (tick % 100 == 0) write_hits();
    if (g_pipe == INVALID_HANDLE_VALUE) continue;
    u64 now = game_ticks();
    for (u32 i = 0; i < g_nprobes; i++) {
      Probe *p = &g_probes[i];
      if (p->pending && now >= p->rearm_at) {
        p->pending = 0;
        if ((u32)p->taken < g_k && (u32)g_seq < g_max && *(u8 *)p->addr == p->orig) {
          put(p, 0xCC);
          p->armed = 1;
        }
      }
    }
  }
  return 0;
}

static u32 load_list(const char *path) {
  HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  u32 size = GetFileSize(h, NULL);
  char *buf = (char *)VirtualAlloc(NULL, size + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  DWORD got = 0;
  if (!buf || !ReadFile(h, buf, size, &got, NULL)) {
    CloseHandle(h);
    return 0;
  }
  CloseHandle(h);
  buf[got] = 0;
  u32 n = 0;
  for (char *s = buf; *s && n < MAXPROBES;) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n' || *s == ',') s++;
    if (*s == '#' || *s == ';') {
      while (*s && *s != '\n') s++;
      continue;
    }
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    u32 v = 0;
    int digits = 0;
    for (;; s++, digits++) {
      char c = *s;
      u32 d = c >= '0' && c <= '9' ? (u32)(c - '0') : c >= 'a' && c <= 'f' ? (u32)(c - 'a' + 10)
                                                     : c >= 'A' && c <= 'F' ? (u32)(c - 'A' + 10) : 99;
      if (d == 99) break;
      v = v * 16 + d;
    }
    if (!digits) {
      while (*s && *s != '\n') s++;
      continue;
    }
    if ((u8 *)v >= g_text_lo && (u8 *)v < g_text_hi) g_probes[n++].addr = v;
    while (*s && *s != '\n' && *s != ',' && *s != ' ') s++;
  }
  // insertion sort is too slow for 30k; a simple shell sort, then drop duplicates
  for (u32 gap = n / 2; gap; gap /= 2)
    for (u32 i = gap; i < n; i++)
      for (u32 j = i; j >= gap && g_probes[j - gap].addr > g_probes[j].addr; j -= gap) {
        u32 t = g_probes[j].addr;
        g_probes[j].addr = g_probes[j - gap].addr;
        g_probes[j - gap].addr = t;
      }
  u32 k = 0;
  for (u32 i = 0; i < n; i++)
    if (!k || g_probes[k - 1].addr != g_probes[i].addr) g_probes[k++].addr = g_probes[i].addr;
  return k;
}

static void shadow_install(void) {
  char buf[600], path[600], *slash = g_dir;
  u32 n = GetModuleFileNameA(NULL, g_dir, sizeof g_dir);
  if (!n || n >= sizeof g_dir) return;
  for (char *q = g_dir; *q; q++)
    if (*q == '\\' || *q == '/') slash = q;
  slash[1] = 0;
  DWORD k = GetEnvironmentVariableA("FF_HYBRID_INI", buf, sizeof buf);
  scpy(scpy(g_ini, g_dir), k && k < sizeof buf ? buf : "hooks.ini");
  cfg("shadow_list", "FF_HYBRID_SHADOW_LIST", "", buf, sizeof buf);
  if (!buf[0]) return;
  scpy(scpy(path, g_dir), "ff_shadow.log");
  g_log = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0x80, NULL);
  scpy(scpy(path, g_dir), buf);

  u8 *exe = (u8 *)GetModuleHandleA(NULL), *nt = exe + *(u32 *)(exe + 0x3c);
  g_text_lo = exe + *(u32 *)(nt + 0xf8 + 12);
  g_text_hi = g_text_lo + *(u32 *)(nt + 0xf8 + 8);
  g_probes = (Probe *)VirtualAlloc(NULL, MAXPROBES * sizeof(Probe), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!g_probes) return;
  g_nprobes = load_list(path);
  slog("functions in the list: ", g_nprobes, 0);
  char v[64];
  cfg("shadow_k", "FF_HYBRID_SHADOW_K", "1", v, sizeof v);
  g_k = pdec(v, 1);
  cfg("shadow_every", "FF_HYBRID_SHADOW_EVERY", "2000", v, sizeof v);
  g_every = pdec(v, 2000);
  cfg("shadow_max", "FF_HYBRID_SHADOW_MAX", "100000", v, sizeof v);
  g_max = pdec(v, 100000);
  cfg("shadow_wait", "FF_HYBRID_SHADOW_WAIT", "60000", v, sizeof v);
  g_wait = pdec(v, 60000);
  slog("samples per function: ", g_k, 0);
  if (!g_nprobes) return;

  // the collector: its pipe, its process (the clone handles go there) and its slot semaphore. shadow_k=0 only
  // records which probes fire (ff_shadow_hits.tsv) and needs no collector.
  if (g_k) {
    cfg("shadow_pipe", "FF_HYBRID_SHADOW_PIPE", "\\\\.\\pipe\\ff_shadow", buf, sizeof buf);
    g_pipe = CreateFileA(buf, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_pipe == INVALID_HANDLE_VALUE) {
      slog("no collector on the pipe; probes not armed, error ", GetLastError(), 1);
      return;
    }
    DWORD pid = 0;
    GetNamedPipeServerProcessId(g_pipe, &pid);
    g_collector = OpenProcess(PROCESS_DUP_HANDLE, 0, pid);
    cfg("shadow_sem", "FF_HYBRID_SHADOW_SEM", "Local\\ff_shadow_slots", buf, sizeof buf);
    g_sem = OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, 0, buf);
    if (!g_collector || !g_sem) {
      slog("collector process or semaphore not reachable, error ", GetLastError(), 1);
      CloseHandle(g_pipe);
      g_pipe = INVALID_HANDLE_VALUE;
      return;
    }
    slog("collector pid ", pid, 0);
  } else {
    slog("shadow_k=0: coverage only, no samples", 0, 2);
  }
  g_qpc = (BOOL(WINAPI *)(u64 *))iat_fn(exe, "QueryPerformanceCounter");
  u64 f = 0;
  QueryPerformanceFrequency(&f);
  if (!(f >> 32) && (u32)f >= 1000) g_tpm = (u32)f / 1000;
  g_clock = (long(__cdecl *)(void))iat_fn(exe, "clock");

  // arm: .text stays writable for the whole run (probes are re-armed from the background thread)
  DWORD old;
  if (!VirtualProtect(g_text_lo, (u32)(g_text_hi - g_text_lo), PAGE_EXECUTE_READWRITE, &old)) {
    slog("VirtualProtect on .text failed, error ", GetLastError(), 1);
    return;
  }
  if (!AddVectoredExceptionHandler(1, (void *)shadow_veh)) {
    slog("AddVectoredExceptionHandler failed", 0, 2);
    return;
  }
  u32 hooked = 0;
  for (u32 i = 0; i < g_nprobes; i++) {
    Probe *p = &g_probes[i];
    p->orig = *(u8 *)p->addr;
    if (p->orig == 0xE9 || p->orig == 0xCC) hooked++;
    p->armed = 1;
    *(u8 *)p->addr = 0xCC;
  }
  FlushInstructionCache(GetCurrentProcess(), g_text_lo, (u32)(g_text_hi - g_text_lo));
  if (hooked) slog("functions starting with a jmp or int3 (hooked? use mode=none): ", hooked, 0);
  CreateThread(NULL, 0, (void *)rearm_thread, NULL, 0, NULL);
  slog("probes armed: ", g_nprobes, 0);
}

BOOL WINAPI ShadowMain(HMODULE self, DWORD reason, void *reserved) {
  BOOL r = DllMain(self, reason, reserved);
  if (reason == 1) shadow_install();
  if (reason == 0 && g_log != INVALID_HANDLE_VALUE) {
    write_hits();
    slog("hits skipped for want of a clone slot: ", (u32)g_skipped, 0);
    slog("samples sent: ", (u32)g_seq, 0);
  }
  return r;
}
