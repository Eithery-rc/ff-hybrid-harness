// dinput8.c - proxy dinput8.dll for the Freedom Fighters hybrid (stage 1).
//
// On process attach: maps the verified ports image (ff_ports.bin) at exactly 0x31000000, checks it and the exe's .text
// against the hashes in ff_hooks.bin, then points each selected exe function at its port with a 5-byte JMP rel32.
// Selection comes from hooks.ini next to the exe (see hybrid/README.md), with FF_HYBRID_* environment overrides.
// DirectInput8Create and the COM exports are forwarded to the system dinput8.dll, loaded on first use.
// No CRT: kernel32 and user32 only. Everything runs inside DllMain, before any exe code.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HMODULE;
typedef long HRESULT;
typedef u32 DWORD;

#define WINAPI __stdcall
#define IMPORT __declspec(dllimport)
#define NULL ((void *)0)
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1
#define OPEN_EXISTING 3
#define CREATE_ALWAYS 2
#define FILE_ATTRIBUTE_NORMAL 0x80
#define MB_ICONERROR 0x10
#define DLL_PROCESS_ATTACH 1

typedef struct {
  u16 wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds;
} SYSTEMTIME;

IMPORT void *WINAPI VirtualAlloc(void *, u32, DWORD, DWORD);
IMPORT BOOL WINAPI VirtualFree(void *, u32, DWORD);
IMPORT BOOL WINAPI VirtualProtect(void *, u32, DWORD, DWORD *);
IMPORT BOOL WINAPI FlushInstructionCache(HANDLE, const void *, u32);
IMPORT HANDLE WINAPI GetCurrentProcess(void);
IMPORT HANDLE WINAPI CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
IMPORT BOOL WINAPI ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
IMPORT BOOL WINAPI WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
IMPORT DWORD WINAPI GetFileSize(HANDLE, DWORD *);
IMPORT BOOL WINAPI CloseHandle(HANDLE);
IMPORT DWORD WINAPI GetModuleFileNameA(HMODULE, char *, DWORD);
IMPORT HMODULE WINAPI GetModuleHandleA(const char *);
IMPORT u32 WINAPI GetSystemDirectoryA(char *, u32);
IMPORT HMODULE WINAPI LoadLibraryA(const char *);
IMPORT void *WINAPI GetProcAddress(HMODULE, const char *);
IMPORT DWORD WINAPI GetEnvironmentVariableA(const char *, char *, DWORD);
IMPORT DWORD WINAPI GetPrivateProfileStringA(const char *, const char *, const char *, char *, DWORD, const char *);
IMPORT void WINAPI GetLocalTime(SYSTEMTIME *);
IMPORT DWORD WINAPI GetLastError(void);
IMPORT void WINAPI OutputDebugStringA(const char *);
IMPORT void WINAPI ExitProcess(u32);
IMPORT int WINAPI MessageBoxA(void *, const char *, const char *, u32);
IMPORT void *WINAPI AddVectoredExceptionHandler(u32, void *);
IMPORT HANDLE WINAPI CreateThread(void *, u32, void *, void *, DWORD, DWORD *);
IMPORT void WINAPI Sleep(DWORD);
IMPORT BOOL WINAPI MoveFileExA(const char *, const char *, DWORD);
IMPORT DWORD WINAPI SetFilePointer(HANDLE, long, long *, DWORD);
IMPORT DWORD WINAPI GetCurrentThreadId(void);
IMPORT u32 WINAPI VirtualQuery(const void *, void *, u32);

int _fltused = 0x9875;  // MSVC marker that floating point is used (no CRT provides it here)

#define PORTS_BASE 0x31000000u
#define EXE_BASE 0x400000u
#define PLAN_MAGIC 0x4b484646u  // 'FFHK'
#define PLAN_VERSION 1
#define ST_OK 0
#define ST_SHORT 1
#define ST_INTERIOR 2
#define VALBUF 0x10000          // one ini value or env var
#define MAXRANGES 0x10000

typedef struct {
  u32 magic, version, image_base, image_size, image_fnv, text_rva, text_size, text_fnv, count, reserved;
} PlanHeader;
typedef struct {
  u32 addr, entry, status;
} PlanEntry;
typedef struct {
  u32 lo, hi;
} Range;

// ---------------------------------------------------------------- small string helpers (no CRT)
static u32 slen(const char *s) {
  u32 n = 0;
  while (s[n]) n++;
  return n;
}
static char *scpy(char *d, const char *s) {
  while ((*d = *s++)) d++;
  return d;
}
static int seq(const char *a, const char *b) {  // case-insensitive equality
  for (;; a++, b++) {
    char x = *a, y = *b;
    if (x >= 'A' && x <= 'Z') x += 32;
    if (y >= 'A' && y <= 'Z') y += 32;
    if (x != y) return 0;
    if (!x) return 1;
  }
}
static char *shex(char *d, u32 v) {
  static const char hx[] = "0123456789abcdef";
  *d++ = '0';
  *d++ = 'x';
  for (int i = 28; i >= 0; i -= 4) *d++ = hx[(v >> i) & 15];
  *d = 0;
  return d;
}
static char *sdec(char *d, u32 v) {
  char t[12];
  int n = 0;
  do t[n++] = (char)('0' + v % 10); while (v /= 10);
  while (n) *d++ = t[--n];
  *d = 0;
  return d;
}
static char *sdec2(char *d, u32 v) {
  *d++ = (char)('0' + v / 10 % 10);
  *d++ = (char)('0' + v % 10);
  *d = 0;
  return d;
}

// ---------------------------------------------------------------- state
static char g_dir[520];        // exe folder, with trailing backslash
static char g_ini[600];
static HANDLE g_log = INVALID_HANDLE_VALUE;
static int g_abort = 1;        // on_error=abort
static HMODULE g_real;

static void path_in_dir(char *out, const char *name) {
  // absolute (drive or UNC) names are used as is
  if ((name[0] && name[1] == ':') || (name[0] == '\\' && name[1] == '\\')) {
    scpy(out, name);
    return;
  }
  scpy(scpy(out, g_dir), name);
}

static void logs(const char *s) {
  DWORD w;
  if (g_log != INVALID_HANDLE_VALUE) WriteFile(g_log, s, slen(s), &w, NULL);
  OutputDebugStringA(s);
}
static void logl(const char *a, const char *b) {
  logs(a);
  if (b) logs(b);
  logs("\r\n");
}
static void logn(const char *a, u32 v, int hex) {
  char t[16];
  if (hex) shex(t, v); else sdec(t, v);
  logs(a);
  logl(t, NULL);
}

static BOOL fail(const char *msg, u32 code) {
  char t[600], *p = scpy(t, "FF hybrid: ");
  p = scpy(p, msg);
  if (code) {
    p = scpy(p, " (");
    p = shex(p, code);
    p = scpy(p, ")");
  }
  logl("ERROR: ", t + 11);
  if (g_abort) {
    scpy(p, "\n\nThe game will close. Set on_error=continue in hooks.ini to run without the ports.");
    MessageBoxA(NULL, t, "Freedom Fighters hybrid", MB_ICONERROR);
    if (g_log != INVALID_HANDLE_VALUE) CloseHandle(g_log);
    ExitProcess(1);
  }
  logl("on_error=continue: running the original exe without ports", NULL);
  return 1;
}

// ini value with environment override: FF_HYBRID_<KEY> wins over hooks.ini [hybrid] <key>
static void cfg(const char *key, const char *envkey, const char *def, char *out, u32 cap) {
  if (envkey && GetEnvironmentVariableA(envkey, out, cap) - 1 < cap - 1) return;
  GetPrivateProfileStringA("hybrid", key, def, out, cap, g_ini);
  if (!out[0]) scpy(out, def);  // an empty "key=" line means the default
}

// ---------------------------------------------------------------- files
static u8 *read_file(const char *path, u32 *size, void *at) {
  HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return NULL;
  u32 n = GetFileSize(h, NULL);
  u8 *buf = at ? (u8 *)at : (u8 *)VirtualAlloc(NULL, n + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  u32 got = 0;
  while (buf && got < n) {
    DWORD r = 0;
    if (!ReadFile(h, buf + got, n - got > 0x100000 ? 0x100000 : n - got, &r, NULL) || !r) break;
    got += r;
  }
  CloseHandle(h);
  if (!buf || got != n) return NULL;
  if (!at) buf[n] = 0;
  *size = n;
  return buf;
}

static u32 fnv(const u8 *p, u32 n) {  // FNV-1a over little-endian dwords, then the tail bytes (matches plan.py)
  u32 h = 0x811c9dc5u, i = 0;
  for (; i + 4 <= n; i += 4) h = (h ^ (p[i] | p[i + 1] << 8 | p[i + 2] << 16 | (u32)p[i + 3] << 24)) * 0x01000193u;
  for (; i < n; i++) h = (h ^ p[i]) * 0x01000193u;
  return h;
}

// ---------------------------------------------------------------- address lists: "0x401000, 4cbec0 0x500000-0x5fffff"
// '#' or ';' starts a comment to the end of the line (useful in include_file / exclude_file).
static int parse_hex(const char **ps, u32 *v) {
  const char *s = *ps;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
  u32 x = 0;
  int n = 0;
  for (;; s++, n++) {
    char c = *s;
    if (c >= '0' && c <= '9') x = x * 16 + (u32)(c - '0');
    else if (c >= 'a' && c <= 'f') x = x * 16 + (u32)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') x = x * 16 + (u32)(c - 'A' + 10);
    else break;
  }
  *ps = s;
  *v = x;
  return n > 0;
}

static u32 parse_ranges(const char *s, Range *r, u32 n) {
  while (*s) {
    char c = *s;
    if (c == '#' || c == ';') {
      while (*s && *s != '\n') s++;
      continue;
    }
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',') {
      s++;
      continue;
    }
    u32 lo, hi;
    if (!parse_hex(&s, &lo)) {  // skip a bad token
      while (*s && *s != ' ' && *s != ',' && *s != '\n') s++;
      continue;
    }
    hi = lo;
    if (*s == '-') {
      s++;
      if (!parse_hex(&s, &hi)) hi = lo;
    }
    if (n < MAXRANGES) {
      r[n].lo = lo;
      r[n].hi = hi;
      n++;
    }
  }
  return n;
}

static u32 load_list(const char *key, const char *envkey, const char *filekey, const char *fileenv, Range *r, char *buf) {
  u32 n = 0, sz;
  cfg(key, envkey, "", buf, VALBUF);
  n = parse_ranges(buf, r, n);
  cfg(filekey, fileenv, "", buf, VALBUF);
  if (buf[0]) {
    char path[600];
    path_in_dir(path, buf);
    u8 *f = read_file(path, &sz, NULL);
    if (!f) {
      fail("cannot read address list file", GetLastError());
      return n;
    }
    n = parse_ranges((const char *)f, r, n);
    VirtualFree(f, 0, MEM_RELEASE);
  }
  return n;
}

static int in_ranges(u32 a, const Range *r, u32 n) {
  for (u32 i = 0; i < n; i++)
    if (a >= r[i].lo && a <= r[i].hi) return 1;
  return 0;
}

// ---------------------------------------------------------------- time_scale: faster game clock
// The exe times frames with CRT clock() and QueryPerformanceCounter (ZSysInterfaceGC::GetTime); its frame delta is
// capped at 0.1 s, so a scale above about 0.1 * fps gains nothing. Each wrapper returns base + (real - base) * scale,
// with the base taken once, so the scaled clocks stay monotonic. Scale is 16.16 fixed point (no CRT float helpers).
// fixed_step=<ms> replaces real time with a virtual clock instead: every IDirect3DDevice8::Present (patched as for
// frame_dump) moves it on by exactly that step, so each frame delta is the step whatever the machine's frame time, and
// the game runs as fast as it renders. The same wrappers serve it; time_scale is then ignored.
typedef unsigned long long u64;
static u32 g_scale_fx;  // 0x10000 = 1.0
static BOOL(WINAPI *o_qpc)(u64 *);
static void(WINAPI *o_systime)(u64 *);
static long(__cdecl *o_clock)(void);
static u64 g_qpc_base, g_systime_base;
static volatile u32 g_clock_base = 0x80000000u;  // unset
static u32 g_step_ms, g_step_qpc;                // fixed_step, and the step in QueryPerformanceCounter ticks
static volatile u32 g_presents;                  // with fixed_step: Present calls so far, the virtual clock
static volatile u32 g_frames = 0xffffffffu;      // Present calls in any mode, once the D3D hooks are in

static u64 scale64(u64 real, u64 base) {
  if (real <= base) return real;
  u64 d = real - base;
  u64 lo = (u64)(u32)d * g_scale_fx, hi = (u64)(u32)(d >> 32) * g_scale_fx;
  return base + (hi << 16) + (lo >> 16);
}
static BOOL WINAPI w_qpc(u64 *out) {
  u64 r;
  if (!o_qpc(&r)) return 0;
  *out = g_step_ms ? g_qpc_base + (u64)g_presents * g_step_qpc : scale64(r, g_qpc_base);
  return 1;
}
static void WINAPI w_systime(u64 *ft) {
  u64 r;
  o_systime(&r);
  *ft = g_step_ms ? g_systime_base + (u64)g_presents * (g_step_ms * 10000u) : scale64(r, g_systime_base);
}
static long __cdecl w_clock(void) {
  long c = o_clock();
  if (c < 0) return c;
  // the CRT may not be initialised while DllMain runs, so the base is taken on the first call
  __sync_val_compare_and_swap(&g_clock_base, 0x80000000u, (u32)c);
  u32 b = g_clock_base;
  if (g_step_ms) return (long)(b + g_presents * g_step_ms);  // clock() counts ms (CLOCKS_PER_SEC 1000)
  if ((u32)c <= b) return c;
  return (long)(b + (u32)(((u64)((u32)c - b) * g_scale_fx) >> 16));
}

static u32 parse_fx(const char *s) {  // "4", "2.5", "0.25" -> 16.16; at most 4 decimals
  u32 ip = 0, fp = 0, div = 1;
  while (*s == ' ') s++;
  for (; *s >= '0' && *s <= '9'; s++) ip = ip * 10 + (u32)(*s - '0');
  if (*s == '.')
    for (s++; *s >= '0' && *s <= '9' && div < 10000; s++) fp = fp * 10 + (u32)(*s - '0'), div *= 10;
  if (ip > 1000) ip = 1000;
  return (ip << 16) + fp * 65536u / div;
}

// Find the exe's IAT slot for an import by name (first match in any DLL), or NULL.
static u32 *iat_find(u8 *exe, const char *name) {
  u8 *nt = exe + *(u32 *)(exe + 0x3c);
  u32 irva = *(u32 *)(nt + 0x80);
  if (!irva) return NULL;
  for (u32 *d = (u32 *)(exe + irva); d[3]; d += 5) {  // IMAGE_IMPORT_DESCRIPTOR: OFT, time, fwd, Name, FirstThunk
    u32 *names = (u32 *)(exe + (d[0] ? d[0] : d[4])), *iat = (u32 *)(exe + d[4]);
    for (u32 i = 0; names[i]; i++)
      if (!(names[i] & 0x80000000u) && seq((const char *)(exe + names[i] + 2), name)) return &iat[i];
  }
  return NULL;
}

// Point an IAT slot at a wrapper; returns the original function, or NULL when the exe does not import it.
static void *iat_hook(u8 *exe, const char *name, void *w, const char *why) {
  u32 *slot = iat_find(exe, name);
  DWORD old;
  if (!slot) return NULL;
  void *orig = (void *)*slot;
  if (!VirtualProtect(slot, 4, PAGE_READWRITE, &old)) {
    logl("VirtualProtect failed on the IAT slot of ", name);
    return NULL;
  }
  *slot = (u32)w;
  VirtualProtect(slot, 4, old, &old);
  logs(why);
  logl(": wrapped ", name);
  return orig;
}

// Point the exe's IAT slots for the timing imports at the wrappers. Returns how many were wrapped.
static u32 wrap_timers(u8 *exe) {
  u32 n = 0, *s;
  const char *why = g_step_ms ? "fixed_step" : "time_scale";
  if ((s = iat_find(exe, "QueryPerformanceCounter"))) {
    o_qpc = (BOOL(WINAPI *)(u64 *))*s;
    o_qpc(&g_qpc_base);
    n += iat_hook(exe, "QueryPerformanceCounter", (void *)w_qpc, why) != NULL;
  }
  if ((s = iat_find(exe, "GetSystemTimeAsFileTime"))) {
    o_systime = (void(WINAPI *)(u64 *))*s;
    o_systime(&g_systime_base);
    n += iat_hook(exe, "GetSystemTimeAsFileTime", (void *)w_systime, why) != NULL;
  }
  if ((s = iat_find(exe, "clock"))) {
    o_clock = (long(__cdecl *)(void))*s;
    n += iat_hook(exe, "clock", (void *)w_clock, why) != NULL;
  }
  if (iat_find(exe, "timeGetTime") || iat_find(exe, "GetTickCount") || iat_find(exe, "GetTickCount64"))
    logl("time_scale: the exe also imports timeGetTime/GetTickCount, which are not wrapped", NULL);
  return n;
}

// ---------------------------------------------------------------- trace: call recorder and crash dump
// With trace=1 every hook jumps to a 45-byte stub instead of straight to the port:
//   pushfd; push eax; mov eax,1; lock xadd [g_pos],eax; and eax,0xff; mov [g_ring+eax*4],<exe addr>;
//   lock inc [hit]; pop eax; popfd; jmp <port>
// so registers, flags and the stack reach the port exactly as the caller left them.
#define RING 256
#define STUB 48
static volatile u32 g_ring[RING];
static volatile u32 g_pos;
static volatile u32 *g_hits;  // per plan entry
static PlanEntry *g_plan;
static u32 g_nplan, g_isize, g_text_lo, g_text_hi, g_exe_end;
static u8 *g_stubs;
static char g_logpath[600], g_hitspath[600], g_hitstmp[620];
static int g_trace, g_max_dumps = 4;
static volatile long g_dumplock, g_dumps, g_probes;
static u32 g_ntdll[2], g_kbase[2], g_k32[2];

typedef struct {
  u32 magic, count, pool;  // 'FFNM'; entries (addr, size, name offset) sorted by addr; then the string pool
} NamesHeader;
static u32 *g_names;  // 3 dwords per entry
static u32 g_nnames;
static const char *g_namepool;

static void put32(u8 *p, u32 v) {
  p[0] = (u8)v;
  p[1] = (u8)(v >> 8);
  p[2] = (u8)(v >> 16);
  p[3] = (u8)(v >> 24);
}

static u8 *make_stub(u8 *p, u32 exe_addr, u32 entry, volatile u32 *hit) {
  *p++ = 0x9C;  // pushfd
  *p++ = 0x50;  // push eax
  *p++ = 0xB8;  // mov eax, 1
  put32(p, 1), p += 4;
  *p++ = 0xF0, *p++ = 0x0F, *p++ = 0xC1, *p++ = 0x05;  // lock xadd [g_pos], eax
  put32(p, (u32)&g_pos), p += 4;
  *p++ = 0x25;  // and eax, 0xff
  put32(p, RING - 1), p += 4;
  *p++ = 0xC7, *p++ = 0x04, *p++ = 0x85;  // mov dword [g_ring + eax*4], exe_addr
  put32(p, (u32)g_ring), p += 4;
  put32(p, exe_addr), p += 4;
  *p++ = 0xF0, *p++ = 0xFF, *p++ = 0x05;  // lock inc dword [hit]
  put32(p, (u32)hit), p += 4;
  *p++ = 0x58;  // pop eax
  *p++ = 0x9D;  // popfd
  *p++ = 0xE9;  // jmp entry
  put32(p, entry - ((u32)p + 4)), p += 4;
  return p;
}

static void load_names(void) {
  char key[260], path[600];
  u32 size;
  cfg("names", "FF_HYBRID_NAMES", "ff_names.bin", key, sizeof key);
  path_in_dir(path, key);
  u8 *f = read_file(path, &size, NULL);
  NamesHeader *h = (NamesHeader *)f;
  if (!f || size < sizeof *h || h->magic != 0x4d4e4646u || sizeof *h + h->count * 12 > size || h->pool > size) {
    logl("names: none loaded (crash dumps show addresses only): ", path);
    return;
  }
  g_names = (u32 *)(h + 1);
  g_nnames = h->count;
  g_namepool = (const char *)f + h->pool;
  logn("names: ", g_nnames, 0);
}

static const char *name_of(u32 a, u32 *off) {  // containing exe function, or NULL
  u32 lo = 0, hi = g_nnames;
  while (lo < hi) {
    u32 m = (lo + hi) / 2;
    if (g_names[m * 3] <= a) lo = m + 1;
    else hi = m;
  }
  if (!lo) return NULL;
  u32 *e = g_names + (lo - 1) * 3;
  if (e[1] && a >= e[0] + e[1]) return NULL;
  *off = a - e[0];
  return g_namepool + e[2];
}

static PlanEntry *port_of(u32 a) {  // plan entry whose port contains a (nearest entry at or below)
  PlanEntry *best = NULL;
  for (u32 i = 0; i < g_nplan; i++)
    if (g_plan[i].entry <= a && (!best || g_plan[i].entry > best->entry)) best = &g_plan[i];
  return best;
}

static void mod_range(const char *name, u32 *r) {
  u8 *m = (u8 *)GetModuleHandleA(name);
  r[0] = r[1] = 0;
  if (!m) return;
  r[0] = (u32)m;
  r[1] = (u32)m + *(u32 *)(m + *(u32 *)(m + 0x3c) + 0x50);  // SizeOfImage
}
static int in_mod(u32 a, const u32 *r) { return a >= r[0] && a < r[1]; }

// append to an open file
static void fw(HANDLE h, const char *s) {
  DWORD w;
  WriteFile(h, s, slen(s), &w, NULL);
}

// "0x00445c50 ZCAMERA::CurrentRoom+0x12" / "0x3105c780 port of 0x00597680 ZGameOSD::..." into d
static char *describe(char *d, u32 a) {
  u32 off;
  d = shex(d, a);
  if (a >= PORTS_BASE && a < PORTS_BASE + g_isize) {
    PlanEntry *e = port_of(a);
    if (e) {
      d = scpy(d, " port of ");
      d = shex(d, e->addr);
      a = e->addr;
      off = 0;
      const char *n = name_of(a, &off);
      if (n && *n) d = scpy(scpy(d, " "), n);
    }
    return d;
  }
  if (g_stubs && a >= (u32)g_stubs && a < (u32)g_stubs + g_nplan * STUB) {
    PlanEntry *e = &g_plan[(a - (u32)g_stubs) / STUB];
    d = scpy(d, " trace stub of ");
    return shex(d, e->addr);
  }
  const char *n = name_of(a, &off);
  if (n) {
    d = scpy(scpy(d, " "), *n ? n : "(unnamed)");
    if (off) {
      d = scpy(d, "+");
      d = shex(d, off);
    }
  }
  return d;
}

static void write_hits(void) {
  if (!g_hits) return;
  HANDLE h = CreateFileA(g_hitstmp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return;
  char line[300], *p;
  u32 off;
  fw(h, "exe_addr\thits\tname\r\n");
  for (u32 i = 0; i < g_nplan; i++) {
    u32 n = g_hits[i];
    if (!n) continue;
    p = shex(line, g_plan[i].addr);
    *p++ = '\t';
    p = sdec(p, n);
    *p++ = '\t';
    const char *nm = name_of(g_plan[i].addr, &off);
    p = scpy(p, nm ? nm : "");
    scpy(p, "\r\n");
    fw(h, line);
  }
  CloseHandle(h);
  MoveFileExA(g_hitstmp, g_hitspath, 1);  // MOVEFILE_REPLACE_EXISTING
}

static DWORD WINAPI hits_thread(void *every) {
  for (;;) {
    Sleep((u32)every * 1000);
    write_hits();
  }
}

#define EXCEPTION_CONTINUE_SEARCH 0
static long WINAPI veh(u32 **ep) {
  u32 *rec = ep[0], *ctx = ep[1];
  u32 code = rec[0], addr = rec[3];
  if (code != 0xC0000005u && code != 0xC000001Du && code != 0xC0000096u && code != 0xC0000094u &&
      code != 0x80000003u)
    return EXCEPTION_CONTINUE_SEARCH;
  // first-chance faults inside the system DLLs are probes (IsBadReadPtr and friends), not crashes
  if (in_mod(addr, g_ntdll) || in_mod(addr, g_kbase) || in_mod(addr, g_k32)) {
    __sync_fetch_and_add(&g_probes, 1);
    return EXCEPTION_CONTINUE_SEARCH;
  }
  if (__sync_fetch_and_add(&g_dumps, 1) >= g_max_dumps) return EXCEPTION_CONTINUE_SEARCH;
  while (__sync_lock_test_and_set(&g_dumplock, 1)) Sleep(0);
  u32 pos = g_pos;  // snapshot before anything else runs
  static u32 ring[RING], uniq[RING], cnt[RING];  // static: the handler may run on a nearly full stack
  for (u32 k = 0; k < RING; k++) ring[k] = g_ring[k];

  HANDLE h = CreateFileA(g_logpath, 4 /* FILE_APPEND_DATA */, FILE_SHARE_READ | 2, NULL, 4 /* OPEN_ALWAYS */,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    char line[400], *p;
    p = scpy(line, "\r\n== crash dump: exception ");
    p = shex(p, code);
    p = scpy(p, " at ");
    p = describe(p, addr);
    if (code == 0xC0000005u && rec[4] >= 2) {
      p = scpy(p, rec[5] == 0 ? ", reading " : rec[5] == 1 ? ", writing " : ", executing ");
      p = shex(p, rec[6]);
    }
    p = scpy(p, ", thread ");
    p = sdec(p, GetCurrentThreadId());
    scpy(p, "\r\n");
    fw(h, line);
    // CONTEXT (x86): Edi 0x9c, Esi 0xa0, Ebx 0xa4, Edx 0xa8, Ecx 0xac, Eax 0xb0, Ebp 0xb4, Eip 0xb8, Esp 0xc4
    static const char *rn[] = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"};
    static const u8 ro[] = {0xb0, 0xa4, 0xac, 0xa8, 0xa0, 0x9c, 0xb4, 0xc4};
    p = scpy(line, "registers:");
    for (int i = 0; i < 8; i++) {
      p = scpy(scpy(p, " "), rn[i]);
      *p++ = '=';
      p = shex(p, *(u32 *)((u8 *)ctx + ro[i]));
    }
    scpy(p, "\r\n");
    fw(h, line);

    // code addresses on the stack (exe .text or ports), bounded by the stack region
    u32 esp = *(u32 *)((u8 *)ctx + 0xc4), mbi[7], shown = 0;
    if (VirtualQuery((void *)esp, mbi, sizeof mbi)) {
      u32 end = mbi[0] + mbi[3];
      fw(h, "stack (code addresses from esp up):\r\n");
      for (u32 *s = (u32 *)esp; (u32)(s + 1) <= end && s < (u32 *)esp + 512 && shown < 24; s++) {
        u32 v = *s;
        if ((v >= g_text_lo && v < g_text_hi) || (v >= PORTS_BASE && v < PORTS_BASE + g_isize)) {
          p = scpy(line, "  [esp+");
          p = shex(p, (u32)s - esp);
          p = scpy(p, "] ");
          p = describe(p, v);
          scpy(p, "\r\n");
          fw(h, line);
          shown++;
        }
      }
    }

    // last hooked calls, newest first, then the distinct set
    u32 n = pos < RING ? pos : RING, nu = 0;
    p = scpy(line, "last ");
    p = sdec(p, n);
    p = scpy(p, " hooked calls, newest first (");
    p = sdec(p, pos);
    scpy(p, " in total):\r\n");
    fw(h, line);
    for (u32 k = 0; k < n; k++) {
      u32 a = ring[(pos - 1 - k) & (RING - 1)], j;
      p = scpy(line, "  -");
      p = sdec(p, k + 1);
      p = scpy(p, " ");
      p = describe(p, a);
      scpy(p, "\r\n");
      fw(h, line);
      for (j = 0; j < nu && uniq[j] != a; j++) {
      }
      if (j == nu) uniq[nu] = a, cnt[nu++] = 0;
      cnt[j]++;
    }
    p = scpy(line, "distinct hooked addresses in the last calls: ");
    p = sdec(p, nu);
    scpy(p, "\r\n");
    fw(h, line);
    for (u32 j = 0; j < nu; j++) {
      p = scpy(line, "  distinct ");
      p = describe(p, uniq[j]);
      p = scpy(p, "  x");
      p = sdec(p, cnt[j]);
      scpy(p, "\r\n");
      fw(h, line);
    }
    p = scpy(line, "== end of crash dump (system-DLL probes skipped so far: ");
    p = sdec(p, (u32)g_probes);
    scpy(p, ")\r\n");
    fw(h, line);
    CloseHandle(h);
  }
  write_hits();
  __sync_lock_release(&g_dumplock);
  return EXCEPTION_CONTINUE_SEARCH;  // the game's own crash handling still runs
}

// ---------------------------------------------------------------- input_script: scripted DirectInput
// What the exe does (ZSysInputGC, devices created from IDirectInput8::EnumDevices):
//   keyboard  c_dfDIKeyboard, SetCooperativeLevel(NONEXCLUSIVE|FOREGROUND), DIPROP_BUFFERSIZE 20, then every frame
//             GetDeviceData (buffered, 20 events, dwOfs = DIK code, dwData & 0x80 = down). No GetDeviceState.
//   mouse     c_dfDIMouse2, SetCooperativeLevel(EXCLUSIVE|FOREGROUND), every frame GetDeviceState(DIMOUSESTATE2).
//   Both re-Acquire in a loop on DIERR_INPUTLOST / DIERR_NOTACQUIRED. Joysticks/XInput are passed through.
// With a script, both devices are forced to BACKGROUND|NONEXCLUSIVE and the injected input is OR-ed with the real
// one (input_real=0 drops the real input). Script times are seconds on this DLL's clock since start: real time
// multiplied by time_scale, counted from the start or from the last satisfied wait_scene.
#define WM_ACTIVATE 0x0006
#define WM_KILLFOCUS 0x0008
#define WM_ACTIVATEAPP 0x001C
IMPORT BOOL WINAPI QueryPerformanceCounter(u64 *);
IMPORT BOOL WINAPI QueryPerformanceFrequency(u64 *);
IMPORT DWORD WINAPI GetTickCount(void);
IMPORT long WINAPI DefWindowProcA(void *, u32, u32, long);

enum { C_KEY, C_DOWN, C_UP, C_MOUSE, C_CLICK, C_WAIT_SCENE, C_QUIT, C_LOG, C_MDOWN, C_MUP, C_CURSOR };
#define MAX_CMDS 65536  // recorded scripts are long
typedef struct {
  u8 type, code;  // code: DIK or mouse button
  u32 line;
  u32 t;          // ms after the current base
  int dx, dy;
  char text[48];  // wait_scene name / log text
} Cmd;
typedef struct {
  void **vtbl;  // our vtable; the forwarding stubs read real at +4
  void *real;
  u32 kind;     // 1 keyboard, 2 mouse
} Wrap;

static int g_input, g_input_real = 1, g_keep_active, g_scene_log;
static Cmd *g_cmds;
static u32 g_ncmds, g_cur, g_base_ms;
static u64 g_t0, g_qpf;
static volatile long g_inlock, g_loglock;
static struct {
  u32 t;
  u8 mouse, code;
} g_rel[64];  // pending releases of key / click
static u32 g_nrel;
static u8 g_kq[256][2];  // keyboard events waiting for GetDeviceData: code, down
static volatile u32 g_kq_head, g_kq_tail;
static u8 g_held[256], g_mbtn[8];
static int g_mdx, g_mdy;
static u32 g_seqno = 0x10000000u;
static char g_scene[260];
static volatile u32 g_scene_seq;
static int g_cx, g_cy, g_cur_set;  // the scripted GUI cursor (C_CURSOR), once a script has set it
static u8 *g_fwd;  // forwarding stubs, one per vtable slot
static void *g_di_vtbl[11], *g_dev_vtbl[32];
static Wrap g_wraps[16];
static volatile long g_nwraps;
static long(WINAPI *o_wndproc)(void *, u32, u32, long);
static u32 g_wndproc_target = 0x421b40;  // the game's main window procedure
static void *(WINAPI *o_createfile)(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
static void *(__cdecl *o_fopen)(const char *, const char *);
static u16(WINAPI *o_registerclass)(u32 *);
static int g_activated;

static void spin(volatile long *l) {
  while (__sync_lock_test_and_set(l, 1)) Sleep(0);
}

// one line appended to the log after DllMain (the start-up handle is closed by then)
static void logx(const char *s) {
  spin(&g_loglock);
  HANDLE h = CreateFileA(g_logpath, 4 /* FILE_APPEND_DATA */, FILE_SHARE_READ | 2, NULL, 4 /* OPEN_ALWAYS */,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    fw(h, s);
    fw(h, "\r\n");
    CloseHandle(h);
  }
  OutputDebugStringA(s);
  __sync_lock_release(&g_loglock);
}

static u32 real_ms(void) {  // real ms since start
  u64 q;
  QueryPerformanceCounter(&q);
  return (u32)(int)((double)(long long)(q - g_t0) * 1000.0 / (double)(long long)g_qpf);
}
static u32 now_ms(void) {  // ms since start on the script clock: the fixed_step clock, or real time x time_scale
  if (g_step_ms) return g_presents * g_step_ms;
  u64 q;
  QueryPerformanceCounter(&q);
  double ms = (double)(long long)(q - g_t0) * 1000.0 / (double)(long long)g_qpf;
  if (g_scale_fx && g_scale_fx != 0x10000) ms = ms * (double)g_scale_fx / 65536.0;
  return (u32)(int)ms;
}
static char *ssec(char *d, u32 ms) {  // "12.345"
  d = sdec(d, ms / 1000);
  *d++ = '.';
  *d++ = (char)('0' + ms / 100 % 10);
  *d++ = (char)('0' + ms / 10 % 10);
  *d++ = (char)('0' + ms % 10);
  *d = 0;
  return d;
}
static char *stime(char *d, u32 ms) { return ssec(scpy(d, "t="), ms); }  // "t=12.345"

// DIK names from dinput.h (DIK_ prefix optional), plus a few aliases; letters, digits and F-keys are computed
static const struct {
  const char *n;
  u8 c;
} g_dik[] = {{"ESCAPE", 0x01}, {"ESC", 0x01}, {"MINUS", 0x0C}, {"EQUALS", 0x0D}, {"BACK", 0x0E}, {"BACKSPACE", 0x0E},
             {"TAB", 0x0F}, {"LBRACKET", 0x1A}, {"RBRACKET", 0x1B}, {"RETURN", 0x1C}, {"ENTER", 0x1C},
             {"LCONTROL", 0x1D}, {"LCTRL", 0x1D}, {"SEMICOLON", 0x27}, {"APOSTROPHE", 0x28}, {"GRAVE", 0x29},
             {"LSHIFT", 0x2A}, {"BACKSLASH", 0x2B}, {"COMMA", 0x33}, {"PERIOD", 0x34}, {"SLASH", 0x35},
             {"RSHIFT", 0x36}, {"MULTIPLY", 0x37}, {"LMENU", 0x38}, {"LALT", 0x38}, {"SPACE", 0x39},
             {"CAPITAL", 0x3A}, {"NUMLOCK", 0x45}, {"SCROLL", 0x46}, {"NUMPAD7", 0x47}, {"NUMPAD8", 0x48},
             {"NUMPAD9", 0x49}, {"SUBTRACT", 0x4A}, {"NUMPAD4", 0x4B}, {"NUMPAD5", 0x4C}, {"NUMPAD6", 0x4D},
             {"ADD", 0x4E}, {"NUMPAD1", 0x4F}, {"NUMPAD2", 0x50}, {"NUMPAD3", 0x51}, {"NUMPAD0", 0x52},
             {"DECIMAL", 0x53}, {"F11", 0x57}, {"F12", 0x58}, {"NUMPADENTER", 0x9C}, {"RCONTROL", 0x9D},
             {"RCTRL", 0x9D}, {"DIVIDE", 0xB5}, {"SYSRQ", 0xB7}, {"RMENU", 0xB8}, {"RALT", 0xB8}, {"PAUSE", 0xC5},
             {"HOME", 0xC7}, {"UP", 0xC8}, {"UPARROW", 0xC8}, {"PRIOR", 0xC9}, {"PGUP", 0xC9}, {"LEFT", 0xCB},
             {"LEFTARROW", 0xCB}, {"RIGHT", 0xCD}, {"RIGHTARROW", 0xCD}, {"END", 0xCF}, {"DOWN", 0xD0},
             {"DOWNARROW", 0xD0}, {"NEXT", 0xD1}, {"PGDN", 0xD1}, {"INSERT", 0xD2}, {"DELETE", 0xD3},
             {"LWIN", 0xDB}, {"RWIN", 0xDC}, {"APPS", 0xDD}};

static u32 dik(const char *s) {  // DIK code, 0 when unknown
  static const char row1[] = "QWERTYUIOP", row2[] = "ASDFGHJKL", row3[] = "ZXCVBNM";
  if ((s[0] == 'D' || s[0] == 'd') && (s[1] == 'I' || s[1] == 'i') && (s[2] == 'K' || s[2] == 'k') && s[3] == '_')
    s += 4;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    u32 v;
    return parse_hex(&s, &v) && v < 256 ? v : 0;
  }
  char c = s[0] >= 'a' && s[0] <= 'z' ? (char)(s[0] - 32) : s[0];
  if (c && !s[1]) {
    if (c >= '1' && c <= '9') return 0x02 + (u32)(c - '1');
    if (c == '0') return 0x0B;
    for (u32 i = 0; row1[i]; i++)
      if (row1[i] == c) return 0x10 + i;
    for (u32 i = 0; row2[i]; i++)
      if (row2[i] == c) return 0x1E + i;
    for (u32 i = 0; row3[i]; i++)
      if (row3[i] == c) return 0x2C + i;
  }
  if (c == 'F' && s[1] >= '1' && s[1] <= '9') {
    u32 f = (u32)(s[1] - '0');
    if (s[2] >= '0' && s[2] <= '9' && !s[3]) f = f * 10 + (u32)(s[2] - '0');
    else if (s[2]) f = 0;
    if (f >= 1 && f <= 10) return 0x3B + f - 1;
  }
  for (u32 i = 0; i < sizeof g_dik / sizeof g_dik[0]; i++)
    if (seq(s, g_dik[i].n)) return g_dik[i].c;
  return 0;
}

// ---- script parsing
static const char *tok(const char *s, char *out, u32 cap) {  // next space-separated token
  u32 n = 0;
  while (*s == ' ' || *s == '\t') s++;
  while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n' && *s != '#') {
    if (n + 1 < cap) out[n++] = *s;
    s++;
  }
  out[n] = 0;
  return s;
}
static int num(const char *s, int *v) {  // signed integer
  int neg = *s == '-', x = 0;
  if (*s == '-' || *s == '+') s++;
  if (!(*s >= '0' && *s <= '9')) return 0;
  for (; *s >= '0' && *s <= '9'; s++) x = x * 10 + (*s - '0');
  *v = neg ? -x : x;
  return !*s;
}
static int secs(const char *s, u32 *ms) {  // "5", "6.25" -> ms
  u32 ip = 0, fr = 0, k = 0;
  if (!(*s >= '0' && *s <= '9') && *s != '.') return 0;
  for (; *s >= '0' && *s <= '9'; s++) ip = ip * 10 + (u32)(*s - '0');
  if (*s == '.')
    for (s++; *s >= '0' && *s <= '9'; s++)
      if (k < 3) fr = fr * 10 + (u32)(*s - '0'), k++;
  while (k < 3) fr *= 10, k++;
  *ms = ip * 1000 + fr;
  return !*s;
}

static void bad_line(u32 line, const char *why) {
  char t[120], *p = scpy(t, "input_script: line ");
  p = sdec(p, line);
  p = scpy(p, " ignored: ");
  scpy(p, why);
  logl(t, NULL);
}

static void load_script(const char *path) {
  u32 size;
  u8 *f = read_file(path, &size, NULL);
  if (!f) {
    fail("cannot read input_script", GetLastError());
    return;
  }
  g_cmds = (Cmd *)VirtualAlloc(NULL, MAX_CMDS * sizeof(Cmd), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!g_cmds) return;
  const char *s = (const char *)f;
  u32 line = 0;
  while (*s && g_ncmds < MAX_CMDS) {
    char w[64], a[64], b[64], c[64];
    line++;
    const char *e = s;
    while (*e && *e != '\n') e++;
    const char *q = tok(s, w, sizeof w);
    Cmd *cm = &g_cmds[g_ncmds];
    cm->line = line;
    cm->t = 0;
    if (!w[0]) {
      // blank or comment
    } else if (seq(w, "wait_scene")) {
      tok(q, a, sizeof a);
      if (!a[0]) bad_line(line, "wait_scene needs a name");
      else {
        cm->type = C_WAIT_SCENE;
        scpy(cm->text, a);
        g_ncmds++;
      }
    } else if (seq(w, "at")) {
      q = tok(q, a, sizeof a);
      if (!secs(a, &cm->t)) bad_line(line, "bad time");
      else {
        q = tok(q, b, sizeof b);
        if (seq(b, "key") || seq(b, "down") || seq(b, "up")) {
          tok(q, c, sizeof c);
          cm->code = (u8)dik(c);
          cm->type = seq(b, "key") ? C_KEY : seq(b, "down") ? C_DOWN : C_UP;
          if (!cm->code) bad_line(line, "unknown key name");
          else g_ncmds++;
        } else if (seq(b, "mouse")) {
          q = tok(q, a, sizeof a);
          tok(q, c, sizeof c);
          cm->type = C_MOUSE;
          if (num(a, &cm->dx) && num(c, &cm->dy)) g_ncmds++;
          else bad_line(line, "mouse needs dx dy");
        } else if (seq(b, "click")) {
          tok(q, c, sizeof c);
          cm->type = C_CLICK;
          cm->code = seq(c, "left") ? 0 : seq(c, "right") ? 1 : seq(c, "middle") ? 2 : 0xff;
          if (cm->code != 0xff) g_ncmds++;
          else bad_line(line, "click left|right|middle");
        } else if (seq(b, "mdown") || seq(b, "mup")) {  // a mouse button held until the matching mup
          tok(q, c, sizeof c);
          cm->type = seq(b, "mdown") ? C_MDOWN : C_MUP;
          cm->code = seq(c, "left") ? 0 : seq(c, "right") ? 1 : seq(c, "middle") ? 2 : 0xff;
          if (cm->code != 0xff) g_ncmds++;
          else bad_line(line, "mdown/mup left|right|middle");
        } else if (seq(b, "cursor")) {  // GUI cursor in client pixels, returned by the exe's ScreenToClient
          q = tok(q, a, sizeof a);
          tok(q, c, sizeof c);
          cm->type = C_CURSOR;
          if (num(a, &cm->dx) && num(c, &cm->dy)) g_ncmds++;
          else bad_line(line, "cursor needs x y");
        } else if (seq(b, "quit")) {
          cm->type = C_QUIT;
          g_ncmds++;
        } else if (seq(b, "log")) {
          cm->type = C_LOG;
          while (*q == ' ' || *q == '\t') q++;
          u32 n = 0;
          while (q < e && *q != '\r' && n + 1 < sizeof cm->text) cm->text[n++] = *q++;
          cm->text[n] = 0;
          g_ncmds++;
        } else
          bad_line(line, "unknown command (key, down, up, mouse, click, mdown, mup, cursor, quit, log)");
      }
    } else
      bad_line(line, "expected 'at <seconds> ...' or 'wait_scene <name>'");
    s = *e ? e + 1 : e;
  }
  VirtualFree(f, 0, MEM_RELEASE);
  logn("input_script: commands: ", g_ncmds, 0);
}

// ---- script execution, driven by the game's own polling of the devices
static void kq_push(u8 code, u8 down) {
  u32 t = g_kq_tail;
  if (t - g_kq_head >= 256) return;  // full: drop
  g_kq[t & 255][0] = code;
  g_kq[t & 255][1] = down;
  g_kq_tail = t + 1;
  g_held[code] = down;
}

static void ev_log(u32 now, const char *what, u32 code, const char *name) {
  char t[160], *p = stime(scpy(t, "input: "), now);
  p = scpy(scpy(p, " "), what);
  if (name) p = scpy(scpy(p, " "), name);
  if (code != 0xffffffffu) {
    p = scpy(p, " ");
    p = shex(p, code);
  }
  logx(t);
}

static void pump(void) {
  if (!g_ncmds && !g_nrel) return;
  spin(&g_inlock);
  u32 now = now_ms();
  for (u32 i = 0; i < g_nrel;) {
    if ((int)(now - g_rel[i].t) >= 0) {
      if (g_rel[i].mouse) g_mbtn[g_rel[i].code] = 0, ev_log(now, "mouse button up", g_rel[i].code, NULL);
      else kq_push(g_rel[i].code, 0), ev_log(now, "key up", g_rel[i].code, NULL);
      g_rel[i] = g_rel[--g_nrel];
    } else
      i++;
  }
  while (g_cur < g_ncmds) {
    Cmd *c = &g_cmds[g_cur];
    if (c->type == C_WAIT_SCENE) {
      // satisfied by the latest scene whose path contains the name (case-insensitive)
      int hit = 0;
      for (const char *s = g_scene; *s && !hit; s++) {
        const char *a = s, *b = c->text;
        while (*a && *b && ((*a | 32) == (*b | 32))) a++, b++;
        hit = !*b;
      }
      if (!hit) break;
      g_base_ms = now;
      ev_log(now, "wait_scene satisfied:", 0xffffffffu, c->text);
    } else {
      if ((int)(now - (g_base_ms + c->t)) < 0) break;
      switch (c->type) {
        case C_KEY:
          kq_push(c->code, 1);
          ev_log(now, "key down", c->code, NULL);
          if (g_nrel < 64) g_rel[g_nrel].t = now + 100, g_rel[g_nrel].mouse = 0, g_rel[g_nrel++].code = c->code;
          break;
        case C_DOWN:
          kq_push(c->code, 1);
          ev_log(now, "key down", c->code, NULL);
          break;
        case C_UP:
          kq_push(c->code, 0);
          ev_log(now, "key up", c->code, NULL);
          break;
        case C_MOUSE: {
          char t[80], *p;
          g_mdx += c->dx;
          g_mdy += c->dy;
          p = scpy(t, "mouse move ");
          p = scpy(p, c->dx < 0 ? "-" : "");
          p = sdec(p, (u32)(c->dx < 0 ? -c->dx : c->dx));
          p = scpy(p, c->dy < 0 ? " -" : " ");
          sdec(p, (u32)(c->dy < 0 ? -c->dy : c->dy));
          ev_log(now, t, 0xffffffffu, NULL);
          break;
        }
        case C_CLICK:
          g_mbtn[c->code] = 1;
          ev_log(now, "mouse button down", c->code, NULL);
          if (g_nrel < 64) g_rel[g_nrel].t = now + 100, g_rel[g_nrel].mouse = 1, g_rel[g_nrel++].code = c->code;
          break;
        case C_MDOWN:
        case C_MUP:
          g_mbtn[c->code] = c->type == C_MDOWN;
          ev_log(now, c->type == C_MDOWN ? "mouse button down" : "mouse button up", c->code, NULL);
          break;
        case C_CURSOR:  // not logged: a recorded script moves it many times a second
          g_cx = c->dx;
          g_cy = c->dy;
          g_cur_set = 1;
          break;
        case C_LOG:
          ev_log(now, "log:", 0xffffffffu, c->text);
          break;
        case C_QUIT:
          ev_log(now, "quit", 0xffffffffu, NULL);
          write_hits();
          ExitProcess(0);
      }
    }
    g_cur++;
    if (g_cur == g_ncmds) ev_log(now, "script finished", 0xffffffffu, NULL);
  }
  __sync_lock_release(&g_inlock);
}

// ---- input_record=<file>: the real input, written in the input_script format so that the file replays it.
// After each scene change the next event first writes `wait_scene <path tail>`, and times count from the first device
// poll of that scene, which is where a replay's wait_scene is satisfied too. Scenes without events are skipped, so a
// replay never waits for a scene it may load past between two polls. Keyboard events come from GetDeviceData
// (down/up), mouse moves and buttons from GetDeviceState (moves summed over 50 ms; mdown/mup), and the GUI cursor
// from the exe's per-frame GetCursorPos + ScreenToClient (0x421e10, windowed and active) as `cursor x y` in client
// pixels, at most every 50 ms. The devices keep the game's own cooperative levels while recording.
static int g_rec;
static HANDLE g_rec_h = INVALID_HANDLE_VALUE;
static volatile long g_reclock;
static u32 g_rec_seen, g_rec_base, g_rec_mt, g_rec_ct;
static int g_rec_wait, g_rec_mdx, g_rec_mdy, g_rec_cx = -100000, g_rec_cy, g_rec_px, g_rec_py, g_rec_cpend;
static u8 g_rec_btn[3];
static char g_rec_name[48];
static BOOL(WINAPI *o_screen2client)(void *, int *);

static char *sint(char *d, int v);
static void rec_put(const char *s) {
  DWORD w;
  WriteFile(g_rec_h, s, slen(s), &w, NULL);
}
static void rec_at(u32 now, const char *what) {  // the callers hold g_reclock
  char t[160], *p;
  if (g_rec_wait) {
    g_rec_wait = 0;
    scpy(scpy(scpy(t, "\r\nwait_scene "), g_rec_name), "\r\n");
    rec_put(t);
  }
  p = ssec(scpy(t, "at "), now - g_rec_base);
  scpy(scpy(scpy(p, " "), what), "\r\n");
  rec_put(t);
}
static void rec_mouse_flush(u32 now) {
  if (g_rec_mdx || g_rec_mdy) {
    char t[48];
    sint(scpy(sint(scpy(t, "mouse "), g_rec_mdx), " "), g_rec_mdy);
    rec_at(now, t);
    g_rec_mdx = g_rec_mdy = 0;
  }
  g_rec_mt = now;
}
static void rec_cursor_flush(u32 now) {
  if (g_rec_cpend) {
    char t[48];
    g_rec_cpend = 0;
    g_rec_cx = g_rec_px;
    g_rec_cy = g_rec_py;
    sint(scpy(sint(scpy(t, "cursor "), g_rec_cx), " "), g_rec_cy);
    rec_at(now, t);
    g_rec_ct = now;
  }
}
static void rec_sync(u32 now) {  // a new scene: what is pending belongs to the old one; times restart here
  if (g_rec_seen == g_scene_seq) return;
  rec_mouse_flush(now);
  rec_cursor_flush(now);
  spin(&g_inlock);
  g_rec_seen = g_scene_seq;
  const char *s = g_scene;  // the path after "Scenes\", at most the last 47 characters
  if ((s[0] | 32) == 's' && (s[1] | 32) == 'c' && (s[2] | 32) == 'e' && (s[3] | 32) == 'n' && (s[4] | 32) == 'e' &&
      (s[5] | 32) == 's' && (s[6] == '/' || s[6] == '\\'))
    s += 7;
  u32 n = slen(s);
  scpy(g_rec_name, n > 47 ? s + n - 47 : s);
  __sync_lock_release(&g_inlock);
  g_rec_base = now;
  g_rec_wait = 1;
}
static void rec_mouse(const u8 *data, u32 cb) {  // DIMOUSESTATE(2): lX, lY, lZ, buttons
  static const char *const names[3] = {"left", "right", "middle"};
  spin(&g_reclock);
  u32 now = now_ms();
  rec_sync(now);
  g_rec_mdx += *(const int *)data;
  g_rec_mdy += *(const int *)(data + 4);
  for (u32 b = 0; b < 3 && 12 + b < cb; b++) {
    u8 d = data[12 + b] & 0x80 ? 1 : 0;
    if (d != g_rec_btn[b]) {
      char t[32];
      rec_cursor_flush(now);
      rec_mouse_flush(now);
      scpy(scpy(t, d ? "mdown " : "mup "), names[b]);
      rec_at(now, t);
      g_rec_btn[b] = d;
    }
  }
  if (now - g_rec_mt >= 50) rec_mouse_flush(now);
  __sync_lock_release(&g_reclock);
}
static void rec_keys(const u8 *ev, u32 n, u32 cb) {  // DIDEVICEOBJECTDATA: dwOfs = DIK code, dwData & 0x80 = down
  static const char hx[] = "0123456789abcdef";
  spin(&g_reclock);
  u32 now = now_ms();
  rec_sync(now);
  for (u32 i = 0; i < n; i++) {
    const u32 *e = (const u32 *)(ev + i * cb);
    char t[32], *p = scpy(t, e[1] & 0x80 ? "down 0x" : "up 0x");
    p[0] = hx[e[0] >> 4 & 15];
    p[1] = hx[e[0] & 15];
    p[2] = 0;
    rec_cursor_flush(now);
    rec_mouse_flush(now);
    rec_at(now, t);
  }
  __sync_lock_release(&g_reclock);
}
// the exe's only ScreenToClient call turns GetCursorPos into the GUI cursor: record it, or with a script that has set
// a cursor, return the scripted one (the parked window's real cursor position means nothing)
static BOOL WINAPI w_screen2client(void *hwnd, int *pt) {
  BOOL r = o_screen2client(hwnd, pt);
  if (!pt) return r;
  if (g_input && g_cur_set) {
    pt[0] = g_cx;
    pt[1] = g_cy;
    return 1;
  }
  if (g_rec && r) {
    spin(&g_reclock);
    u32 now = now_ms();
    rec_sync(now);
    g_rec_px = pt[0];
    g_rec_py = pt[1];
    g_rec_cpend = g_rec_px != g_rec_cx || g_rec_py != g_rec_cy;
    if (g_rec_cpend && now - g_rec_ct >= 50) rec_cursor_flush(now);
    __sync_lock_release(&g_reclock);
  }
  return r;
}

// ---- COM wrappers. Unwrapped slots go through a 19-byte stub that swaps `this` for the real object:
//   mov eax,[esp+4]; mov eax,[eax+4]; mov [esp+4],eax; mov eax,[eax]; jmp [eax+slot*4]
static void make_fwd(void) {
  g_fwd = (u8 *)VirtualAlloc(NULL, 32 * 20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!g_fwd) return;
  for (u32 k = 0; k < 32; k++) {
    u8 *p = g_fwd + k * 20;
    static const u8 head[] = {0x8B, 0x44, 0x24, 0x04, 0x8B, 0x40, 0x04, 0x89, 0x44, 0x24, 0x04, 0x8B, 0x00, 0xFF, 0xA0};
    for (u32 i = 0; i < sizeof head; i++) p[i] = head[i];
    put32(p + sizeof head, k * 4);
  }
}
static void *real_slot(Wrap *w, u32 k) { return (*(void ***)w->real)[k]; }
static void *wrap_obj(void *real, void **vtbl, u32 kind) {
  long i = __sync_fetch_and_add(&g_nwraps, 1);
  if (i >= 16) return real;  // out of wrappers: hand out the real object
  g_wraps[i].vtbl = vtbl;
  g_wraps[i].real = real;
  g_wraps[i].kind = kind;
  return &g_wraps[i];
}

static const u8 GUID_SysKeyboard[16] = {0x61, 0x2B, 0x1D, 0x6F, 0xA0, 0xD5, 0xCF, 0x11,
                                        0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
static int guid_is(const u8 *g, const u8 *want, u8 first) {
  if (!g || g[0] != first) return 0;
  for (int i = 1; i < 16; i++)
    if (g[i] != want[i]) return 0;
  return 1;
}

static HRESULT WINAPI di_create_device(Wrap *w, const u8 *guid, void **out, void *outer) {
  HRESULT r = ((HRESULT(WINAPI *)(void *, const u8 *, void **, void *))real_slot(w, 3))(w->real, guid, out, outer);
  u32 kind = guid_is(guid, GUID_SysKeyboard, 0x61) ? 1 : guid_is(guid, GUID_SysKeyboard, 0x60) ? 2 : 0;
  if (r >= 0 && out && *out && kind) {
    *out = wrap_obj(*out, g_dev_vtbl, kind);
    logx(kind == 1 ? "input: keyboard device wrapped" : "input: mouse device wrapped");
  }
  return r;
}

static HRESULT WINAPI dev_coop(Wrap *w, void *hwnd, DWORD flags) {
  DWORD f = g_input ? 0xA : flags;  // DISCL_BACKGROUND | DISCL_NONEXCLUSIVE
  HRESULT r = ((HRESULT(WINAPI *)(void *, void *, DWORD))real_slot(w, 13))(w->real, hwnd, f);
  char t[120], *p = scpy(t, w->kind == 1 ? "input: keyboard" : "input: mouse");
  p = shex(scpy(p, " SetCooperativeLevel "), flags);
  p = shex(scpy(p, " -> "), f);
  shex(scpy(p, ", result "), (u32)r);
  logx(t);
  return r;
}

static volatile long g_acq_logs;
static HRESULT WINAPI dev_acquire(Wrap *w) {
  HRESULT r = ((HRESULT(WINAPI *)(void *))real_slot(w, 7))(w->real);
  if (r < 0 && __sync_fetch_and_add(&g_acq_logs, 1) < 8) {
    char t[80];
    shex(scpy(scpy(t, w->kind == 1 ? "input: keyboard" : "input: mouse"), " Acquire failed "), (u32)r);
    logx(t);
  }
  return r;
}
static HRESULT WINAPI dev_unacquire(Wrap *w) {
  return ((HRESULT(WINAPI *)(void *))real_slot(w, 8))(w->real);
}

static HRESULT WINAPI dev_state(Wrap *w, DWORD cb, u8 *data) {
  HRESULT r = ((HRESULT(WINAPI *)(void *, DWORD, void *))real_slot(w, 9))(w->real, cb, data);
  if (g_rec && r >= 0 && data && w->kind == 2 && cb >= 16) rec_mouse(data, cb);
  if (!g_input || !data) return r;
  pump();
  if (r < 0) return r;  // the game re-acquires; nothing to add to
  if (!g_input_real)
    for (u32 i = 0; i < cb; i++) data[i] = 0;
  if (w->kind == 2 && cb >= 16) {  // DIMOUSESTATE(2): lX, lY, lZ, buttons
    spin(&g_inlock);
    *(int *)data += g_mdx;
    *(int *)(data + 4) += g_mdy;
    g_mdx = g_mdy = 0;
    for (u32 b = 0; b < 8 && 12 + b < cb; b++)
      if (g_mbtn[b]) data[12 + b] |= 0x80;
    __sync_lock_release(&g_inlock);
  } else if (w->kind == 1 && cb >= 256) {
    for (u32 k = 0; k < 256; k++)
      if (g_held[k]) data[k] |= 0x80;
  }
  return r;
}

static HRESULT WINAPI dev_data(Wrap *w, DWORD cb, u8 *rgdod, DWORD *inout, DWORD flags) {
  DWORD cap = inout ? *inout : 0;
  HRESULT r = ((HRESULT(WINAPI *)(void *, DWORD, void *, DWORD *, DWORD))real_slot(w, 10))(w->real, cb, rgdod, inout,
                                                                                        flags);
  if (g_rec && r >= 0 && w->kind == 1 && inout && rgdod && cb >= 16 && !(flags & 1)) rec_keys(rgdod, *inout, cb);
  if (!g_input || w->kind != 1 || !inout || !rgdod || cb < 16) return r;
  pump();
  int real_failed = r < 0;
  if (real_failed && g_kq_head == g_kq_tail) return r;  // let the game re-acquire
  u32 n = real_failed || !g_input_real ? 0 : *inout;
  spin(&g_inlock);
  u32 h = g_kq_head;
  while (n < cap && h != g_kq_tail) {
    u32 *e = (u32 *)(rgdod + n * cb);  // DIDEVICEOBJECTDATA: dwOfs, dwData, dwTimeStamp, dwSequence, uAppData
    e[0] = g_kq[h & 255][0];
    e[1] = g_kq[h & 255][1] ? 0x80 : 0;
    e[2] = GetTickCount();
    e[3] = g_seqno++;
    if (cb >= 20) e[4] = 0;
    h++;
    n++;
  }
  if (!(flags & 1)) g_kq_head = h;  // DIGDD_PEEK leaves them queued
  __sync_lock_release(&g_inlock);
  *inout = n;
  return real_failed ? 0 : r;
}

// ---- keep_active: the game's window procedure never sees itself lose focus, and gets one activation
static long WINAPI w_wndproc(void *h, u32 msg, u32 wp, long lp) {
  if (!g_activated && g_exe_end > 0x7003a4 && *(volatile u32 *)0x7003a0) {
    // the input system exists (ZSysInputGC at 0x7003a0): activate once, as a focused start would
    g_activated = 1;
    o_wndproc(h, WM_ACTIVATE, 1, 0);
    o_wndproc(h, 0x0007 /* WM_SETFOCUS */, 0, 0);
    logx("keep_active: sent WM_ACTIVATE and WM_SETFOCUS to the game window");
  }
  if (msg == WM_KILLFOCUS || (msg == WM_ACTIVATE && !(wp & 0xffff)) || (msg == WM_ACTIVATEAPP && !wp))
    return DefWindowProcA(h, msg, wp, lp);
  return o_wndproc(h, msg, wp, lp);
}
static u16 WINAPI w_registerclass(u32 *wc) {  // WNDCLASSEXA: cbSize, style, lpfnWndProc, ...
  if (wc && wc[2] == g_wndproc_target && !o_wndproc) {
    o_wndproc = (long(WINAPI *)(void *, u32, u32, long))wc[2];
    wc[2] = (u32)w_wndproc;
    u16 r = o_registerclass(wc);
    wc[2] = (u32)o_wndproc;
    logx("keep_active: game window procedure wrapped");
    return r;
  }
  return o_registerclass(wc);
}

// ---- scene log: the first open of each new Scenes\*.zip path
static void scene_check(const char *path) {
  if (!path) return;
  u32 n = slen(path);
  if (n < 4 || !seq(path + n - 4, ".zip")) return;
  spin(&g_inlock);
  int same = seq(path, g_scene);
  if (!same && n < sizeof g_scene) {
    scpy(g_scene, path);
    g_scene_seq++;
  }
  __sync_lock_release(&g_inlock);
  if (!same) {
    char t[340], *p = stime(scpy(t, "scene: "), now_ms());
    if (g_frames != 0xffffffffu) {  // with the D3D hooks: wall clock seconds and frames, to measure the speed
      p = ssec(scpy(p, " real="), real_ms());
      p = sdec(scpy(p, " frames="), g_frames);
    }
    scpy(scpy(p, " "), path);
    logx(t);
  }
}
#ifdef LOG_OPENS  // test builds (-DLOG_OPENS): every path the exe opens or searches goes to the log
static void log_open(const char *what, const char *n) {
  char t[400], *p = scpy(scpy(t, "open: "), what);
  for (u32 i = 0; n && n[i] && i < 300; i++) *p++ = n[i];
  *p = 0;
  logx(t);
}
static HANDLE(WINAPI *o_findfirst)(const char *, void *);
static HANDLE WINAPI w_findfirst(const char *n, void *fd) {
  log_open("FindFirstFileA ", n);
  return o_findfirst(n, fd);
}
#else
#define log_open(what, n)
#endif
static void *WINAPI w_createfile(const char *n, DWORD a, DWORD s, void *sa, DWORD c, DWORD f, HANDLE t) {
  log_open(a & GENERIC_WRITE ? "CreateFileA write " : "CreateFileA ", n);
  void *h = o_createfile(n, a, s, sa, c, f, t);
  if (h != INVALID_HANDLE_VALUE) scene_check(n);
  return h;
}
static void *__cdecl w_fopen(const char *n, const char *m) {
  log_open(m && m[0] != 'r' ? "fopen write " : "fopen ", n);
  void *h = o_fopen(n, m);
  if (h) scene_check(n);
  return h;
}

// ---------------------------------------------------------------- frame_dump: back buffer snapshots as BMP files
// PrintWindow sees nothing of a D3D window parked off-screen, so the loader reads the back buffer itself.
// Direct3DCreate8 is wrapped in the exe's IAT; IDirect3D8::CreateDevice (slot 15) and IDirect3DDevice8::Reset (slot 14)
// add D3DPRESENTFLAG_LOCKABLE_BACKBUFFER, and IDirect3DDevice8::Present (slot 15) first writes the back buffer to
// <frame_dump_dir>\<seconds>.bmp (24-bit) every frame_dump_every seconds on the script clock. The slots are patched in
// d3d8.dll's shared vtables. A run starts by deleting the old frames and keeps only the last frame_dump_keep files.
// The same Present wrapper moves the fixed_step clock, and with present_every_ms=N it passes a frame on to the real
// Present only when N real ms have gone by since the last one: Present to a window parked off-screen blocks for about
// 42 ms (measured 2026-10-22), which held the game to about 24 frames per second.
IMPORT BOOL WINAPI CreateDirectoryA(const char *, void *);
IMPORT BOOL WINAPI DeleteFileA(const char *);
IMPORT HANDLE WINAPI FindFirstFileA(const char *, void *);
IMPORT BOOL WINAPI FindNextFileA(HANDLE, void *);
IMPORT BOOL WINAPI FindClose(HANDLE);

#define LOCKABLE_BACKBUFFER 1  // D3DPRESENTFLAG_LOCKABLE_BACKBUFFER
#define MAXKEEP 256
typedef struct {
  u32 head[11];  // attributes, three FILETIMEs, size high/low, two reserved
  char name[260];
  char alt[16];
} FindData;      // WIN32_FIND_DATAA

static void *(WINAPI *o_d3dcreate)(u32);
static HRESULT(WINAPI *o_createdev)(void *, u32, u32, void *, DWORD, u32 *, void **);
static HRESULT(WINAPI *o_reset)(void *, u32 *);
static HRESULT(WINAPI *o_present)(void *, const void *, const void *, void *, const void *);
static char g_framedir[600];
static int g_frame_dump;
static u32 g_present_every, g_last_present;  // present_every_ms: real ms between Presents that reach the window
static u32 g_frame_every, g_frame_next, g_frame_keep, g_nframes, g_frame_fbuf_size;
static u32 g_frame_t[MAXKEEP];  // seconds (= file names) of the kept frames, a ring
static u8 *g_fbuf;
static volatile long g_frame_logs;

static void frame_log(const char *what, u32 v) {  // at most 12 lines per run
  if (__sync_fetch_and_add(&g_frame_logs, 1) >= 12) return;
  char t[160], *p = scpy(scpy(t, "frame_dump: "), what);
  if (v != 0xffffffffu) shex(scpy(p, " "), v);
  logx(t);
}

static void frame_path(char *out, u32 sec, const char *ext) {  // <dir>00185.bmp
  char t[12], *p = scpy(out, g_framedir);
  u32 n = (u32)(sdec(t, sec) - t);
  for (; n < 5; n++) *p++ = '0';
  scpy(scpy(p, t), ext);
}

// Patch one slot of a shared vtable; returns the original, or NULL when it is already ours or not writable.
// EXECUTE_READWRITE because system DLLs often merge .rdata into .text.
static void *vt_patch(void **vt, u32 slot, void *w) {
  DWORD old;
  void *orig = vt[slot];
  if (orig == w || !VirtualProtect(&vt[slot], 4, PAGE_EXECUTE_READWRITE, &old)) return NULL;
  vt[slot] = w;
  VirtualProtect(&vt[slot], 4, old, &old);
  return orig;
}

static void dump_frame(void *dev, u32 now) {
  void **dv = *(void ***)dev, *s = NULL;
  u32 desc[8], lr[2];  // D3DSURFACE_DESC: Format, Type, Usage, Pool, Size, MultiSampleType, Width, Height; LOCKED_RECT
  if (((HRESULT(WINAPI *)(void *, u32, u32, void **))dv[16])(dev, 0, 0, &s) < 0 || !s) {  // GetBackBuffer
    frame_log("GetBackBuffer failed", 0xffffffffu);
    return;
  }
  void **sv = *(void ***)s;
  u32 fmt = 0, w = 0, h = 0, bpp = 0;
  if (((HRESULT(WINAPI *)(void *, u32 *))sv[8])(s, desc) >= 0) fmt = desc[0], w = desc[6], h = desc[7];  // GetDesc
  // D3DFMT_R8G8B8 20, A8R8G8B8 21, X8R8G8B8 22, R5G6B5 23, X1R5G5B5 24, A1R5G5B5 25
  bpp = fmt == 21 || fmt == 22 ? 4 : fmt == 20 ? 3 : fmt >= 23 && fmt <= 25 ? 2 : 0;
  u32 stride = (w * 3 + 3) & ~3u, size = 54 + stride * h;
  if (!bpp || !w || !h || w > 8192 || h > 8192) {
    frame_log("unsupported back buffer format", fmt);
    ((u32(WINAPI *)(void *))sv[2])(s);
    return;
  }
  if (size > g_frame_fbuf_size) {
    if (g_fbuf) VirtualFree(g_fbuf, 0, MEM_RELEASE);
    g_fbuf = (u8 *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_frame_fbuf_size = g_fbuf ? size : 0;
  }
  // LockRect, read only; fails on a lost device or a back buffer created without the lockable flag
  if (!g_fbuf || ((HRESULT(WINAPI *)(void *, u32 *, const void *, DWORD))sv[9])(s, lr, NULL, 0x10) < 0) {
    frame_log("LockRect failed, frame skipped", 0xffffffffu);
    ((u32(WINAPI *)(void *))sv[2])(s);
    return;
  }
  u8 *o = g_fbuf + 54;
  for (u32 y = 0; y < h; y++, o += stride) {
    const u8 *row = (const u8 *)lr[1] + (int)(h - 1 - y) * (int)lr[0];  // BMP rows go bottom-up
    u8 *d = o;
    for (u32 x = 0; x < w; x++, d += 3) {
      if (bpp == 4) d[0] = row[x * 4], d[1] = row[x * 4 + 1], d[2] = row[x * 4 + 2];
      else if (bpp == 3) d[0] = row[x * 3], d[1] = row[x * 3 + 1], d[2] = row[x * 3 + 2];
      else {
        u32 v = row[x * 2] | (u32)row[x * 2 + 1] << 8, r, g, b = v & 31;
        if (fmt == 23) r = v >> 11, g = v >> 5 & 63, g = g << 2 | g >> 4;
        else r = v >> 10 & 31, g = v >> 5 & 31, g = g << 3 | g >> 2;
        d[0] = (u8)(b << 3 | b >> 2), d[1] = (u8)g, d[2] = (u8)(r << 3 | r >> 2);
      }
    }
  }
  ((HRESULT(WINAPI *)(void *))sv[10])(s);  // UnlockRect
  ((u32(WINAPI *)(void *))sv[2])(s);       // Release
  u8 *b = g_fbuf;  // BITMAPFILEHEADER + BITMAPINFOHEADER, 24 bits, bottom-up
  for (u32 i = 0; i < 54; i++) b[i] = 0;
  b[0] = 'B', b[1] = 'M';
  put32(b + 2, size);
  put32(b + 10, 54);
  put32(b + 14, 40);
  put32(b + 18, w);
  put32(b + 22, h);
  b[26] = 1, b[28] = 24;
  put32(b + 34, stride * h);
  put32(b + 38, 2835), put32(b + 42, 2835);

  // write a .tmp and rename it, so a reader never sees half a file
  char path[620], tmp[620];
  u32 sec = now / 1000;
  frame_path(path, sec, ".bmp");
  frame_path(tmp, sec, ".tmp");
  HANDLE f = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD wr = 0;
  if (f == INVALID_HANDLE_VALUE) {
    frame_log("cannot create the frame file", GetLastError());
    return;
  }
  BOOL ok = WriteFile(f, g_fbuf, size, &wr, NULL) && wr == size;
  CloseHandle(f);
  if (!ok || !MoveFileExA(tmp, path, 1)) {  // MOVEFILE_REPLACE_EXISTING
    DeleteFileA(tmp);
    frame_log("cannot write the frame file", GetLastError());
    return;
  }
  u32 k = g_nframes % g_frame_keep;
  if (g_nframes >= g_frame_keep && g_frame_t[k] != sec) {
    frame_path(tmp, g_frame_t[k], ".bmp");
    DeleteFileA(tmp);
  }
  g_frame_t[k] = sec;
  if (!g_nframes++) {
    char t[700], *p = stime(scpy(t, "frame_dump: first frame "), now);
    p = sdec(scpy(scpy(scpy(p, " "), path), " "), w);
    p = sdec(scpy(p, "x"), h);
    sdec(scpy(p, " format "), fmt);
    logx(t);
  }
}

static HRESULT WINAPI w_present(void *dev, const void *src, const void *dst, void *hwnd, const void *dirty) {
  if (g_frame_dump) {
    u32 now = now_ms();
    if ((int)(now - g_frame_next) >= 0) {
      g_frame_next = now + g_frame_every;
      dump_frame(dev, now);
    }
  }
  // present_every_ms: only some frames reach the window. The game sees D3D_OK and runs the same either way.
  HRESULT r = 0;
  u32 real = g_present_every ? real_ms() : 0;
  if (!g_present_every || real - g_last_present >= g_present_every) {
    r = o_present(dev, src, dst, hwnd, dirty);
    g_last_present = real;
  }
  if (g_step_ms) __sync_fetch_and_add(&g_presents, 1);  // fixed_step: the next frame starts one step later
  g_frames++;
  return r;
}

// D3DPRESENT_PARAMETERS (D3D8), dwords: MultiSampleType [4], Flags [10]. A lockable back buffer cannot be multisampled;
// when the device refuses the flag, the call is repeated as the game made it. The game's Flags are restored after.
static HRESULT WINAPI w_reset(void *dev, u32 *pp) {
  u32 had = pp ? pp[10] : 0;
  if (g_frame_dump && pp && !pp[4]) pp[10] |= LOCKABLE_BACKBUFFER;
  HRESULT r = o_reset(dev, pp);
  if (r < 0 && pp && pp[10] != had) {
    pp[10] = had;
    r = o_reset(dev, pp);
    frame_log("Reset refused the lockable back buffer; frames stop", (u32)r);
  }
  if (pp) pp[10] = had;
  return r;
}

static HRESULT WINAPI w_createdev(void *d3d, u32 adapter, u32 type, void *hwnd, DWORD flags, u32 *pp, void **out) {
  u32 had = pp ? pp[10] : 0;
  if (g_frame_dump && pp && !pp[4]) pp[10] |= LOCKABLE_BACKBUFFER;
  HRESULT r = o_createdev(d3d, adapter, type, hwnd, flags, pp, out);
  if (r < 0 && pp && pp[10] != had) {
    pp[10] = had;
    r = o_createdev(d3d, adapter, type, hwnd, flags, pp, out);
    frame_log("CreateDevice refused the lockable back buffer; frames will fail", (u32)r);
  }
  if (pp) pp[10] = had;
  if (r >= 0 && out && *out) {
    void **vt = *(void ***)*out, *o;
    if ((o = vt_patch(vt, 15, (void *)w_present))) o_present = (HRESULT(WINAPI *)(void *, const void *, const void *,
                                                                                  void *, const void *))o;
    if ((o = vt_patch(vt, 14, (void *)w_reset))) o_reset = (HRESULT(WINAPI *)(void *, u32 *))o;
    char t[160], *p = scpy(t, "d3d: device created ");
    p = sdec(p, pp ? pp[0] : 0);
    p = sdec(scpy(p, "x"), pp ? pp[1] : 0);
    p = sdec(scpy(p, " format "), pp ? pp[2] : 0);
    p = sdec(scpy(p, " windowed "), pp ? pp[7] : 0);
    scpy(p, o_present ? ", Present and Reset patched" : ", Present NOT patched");
    logx(t);
  }
  return r;
}

static void *WINAPI w_d3dcreate(u32 sdk) {
  void *d3d = o_d3dcreate(sdk), *o;
  if (d3d && (o = vt_patch(*(void ***)d3d, 15, (void *)w_createdev)))
    o_createdev = (HRESULT(WINAPI *)(void *, u32, u32, void *, DWORD, u32 *, void **))o;
  return d3d;
}

static void setup_frames(char *buf);

// frame_dump options, then the Direct3D hooks, which both frame_dump and fixed_step need
static void setup_d3d(u8 *exe, char *buf) {
  cfg("frame_dump", "FF_HYBRID_FRAME_DUMP", "0", buf, VALBUF);
  g_frame_dump = buf[0] == '1';
  if (g_frame_dump) setup_frames(buf);
  cfg("present_every_ms", "FF_HYBRID_PRESENT_EVERY_MS", "0", buf, VALBUF);
  g_present_every = 0;
  for (const char *q = buf; *q >= '0' && *q <= '9' && g_present_every < 100000; q++)
    g_present_every = g_present_every * 10 + (u32)(*q - '0');
  if (g_present_every) logn("present_every_ms: frames reach the window at most every (real ms): ", g_present_every, 0);
  if (!g_frame_dump && !g_step_ms && !g_present_every) return;
  o_d3dcreate = (void *(WINAPI *)(u32))iat_hook(exe, "Direct3DCreate8", (void *)w_d3dcreate, "d3d");
  if (o_d3dcreate) g_frames = 0;
  if (!o_d3dcreate) {
    logl("d3d: the exe does not import Direct3DCreate8; no frames, fixed_step off", NULL);
    g_frame_dump = 0;
    g_step_ms = 0;  // a virtual clock that Present never moves would stop the game
  }
}

static void setup_frames(char *buf) {
  cfg("frame_dump_every", "FF_HYBRID_FRAME_DUMP_EVERY", "5", buf, VALBUF);
  if (!secs(buf, &g_frame_every)) g_frame_every = 5000;
  if (g_frame_every < 1000) g_frame_every = 1000;  // file names are whole seconds
  cfg("frame_dump_keep", "FF_HYBRID_FRAME_DUMP_KEEP", "40", buf, VALBUF);
  g_frame_keep = 0;
  for (const char *q = buf; *q >= '0' && *q <= '9'; q++) g_frame_keep = g_frame_keep * 10 + (u32)(*q - '0');
  if (!g_frame_keep || g_frame_keep > MAXKEEP) g_frame_keep = g_frame_keep ? MAXKEEP : 40;
  cfg("frame_dump_dir", "FF_HYBRID_FRAME_DUMP_DIR", "frames", buf, VALBUF);
  path_in_dir(g_framedir, buf);
  char *e = g_framedir + slen(g_framedir);
  if (e[-1] != '\\' && e[-1] != '/') scpy(e, "\\");
  CreateDirectoryA(g_framedir, NULL);

  // the frames of an earlier run would pass for this run's
  static FindData fd;
  char pat[620], path[620];
  u32 gone = 0;
  for (int pass = 0; pass < 2; pass++) {
    scpy(scpy(pat, g_framedir), pass ? "*.tmp" : "*.bmp");
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) continue;
    do {
      scpy(scpy(path, g_framedir), fd.name);
      gone += DeleteFileA(path) != 0;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
  }
  g_frame_next = g_frame_every;
  char line[700], *p = scpy(line, "frame_dump: every ");
  p = sdec(p, g_frame_every);
  p = sdec(scpy(p, " ms (script clock), keep "), g_frame_keep);
  p = scpy(scpy(p, ", into "), g_framedir);
  sdec(scpy(p, ", old frames deleted: "), gone);
  logl(line, NULL);
}

// ---------------------------------------------------------------- window_park: the game window off the desktop
// Test runs keep the game window right of the whole virtual desktop (x = SM_XVIRTUALSCREEN + SM_CXVIRTUALSCREEN + 100,
// y = 100; a negative position crashes the original game) without editing freedom.ini, which every instance and the
// user's own game share. CreateWindowExA, SetWindowPos and MoveWindow get the parked position for top-level windows,
// which are also created WS_EX_NOACTIVATE and only ever shown without activation. SetForegroundWindow, ClipCursor and
// SetCursorPos do nothing, so a run never takes the focus or the mouse; keep_active makes the game believe it is
// active. A message box (the crash reporter's) ends the process instead of showing. Windowed mode itself (Window 1)
// still comes from freedom.ini.
#define WS_CHILD 0x40000000u
#define WS_EX_NOACTIVATE 0x08000000u
#define SWP_NOMOVE 0x2
#define SWP_NOACTIVATE 0x10
IMPORT int WINAPI GetSystemMetrics(int);

static void *g_parked[8];
static volatile long g_nparked, g_park_logs;
static void *(WINAPI *o_createwindow)(DWORD, const char *, const char *, DWORD, int, int, int, int, void *, void *,
                                      void *, void *);
static BOOL(WINAPI *o_setwindowpos)(void *, void *, int, int, int, int, u32);
static BOOL(WINAPI *o_movewindow)(void *, int, int, int, int, BOOL);
static BOOL(WINAPI *o_showwindow)(void *, int);

#ifndef PARK_GAP
#define PARK_GAP 100  // a test build can move it (-DPARK_GAP=400) to tell the loader's parking from an ini-parked one
#endif
static void park_xy(int *x, int *y) {
  int r = GetSystemMetrics(76) + GetSystemMetrics(78) + PARK_GAP;  // SM_XVIRTUALSCREEN + SM_CXVIRTUALSCREEN
  *x = r > 0 ? r : 0;
  *y = 100;
}
static int parked(void *h) {
  for (long i = 0; i < g_nparked && i < 8; i++)
    if (g_parked[i] == h) return 1;
  return 0;
}
static char *sint(char *d, int v) { return v < 0 ? sdec(scpy(d, "-"), 0u - (u32)v) : sdec(d, (u32)v); }
static void park_log(const char *what, int x, int y, int px, int py) {  // at most 16 lines per run
  if (__sync_fetch_and_add(&g_park_logs, 1) >= 16) return;
  char t[160], *p = scpy(scpy(t, "window_park: "), what);
  if (px != -1) {
    p = sint(scpy(p, " "), x);
    p = sint(scpy(p, ","), y);
    p = sint(scpy(p, " -> "), px);
    sint(scpy(p, ","), py);
  }
  logx(t);
}

static void *WINAPI w_createwindow(DWORD ex, const char *cls, const char *name, DWORD style, int x, int y, int w,
                                   int h, void *parent, void *menu, void *inst, void *param) {
  if (style & WS_CHILD) return o_createwindow(ex, cls, name, style, x, y, w, h, parent, menu, inst, param);
  int px, py;
  park_xy(&px, &py);
  void *hw = o_createwindow(ex | WS_EX_NOACTIVATE, cls, name, style, px, py, w, h, parent, menu, inst, param);
  if (hw) {
    long i = __sync_fetch_and_add(&g_nparked, 1);
    if (i < 8) g_parked[i] = hw;
  }
  park_log("CreateWindowExA", x, y, px, py);
  return hw;
}
static BOOL WINAPI w_setwindowpos(void *h, void *after, int x, int y, int cx, int cy, u32 flags) {
  if (parked(h)) {
    if (!(flags & SWP_NOMOVE)) {
      int px, py;
      park_xy(&px, &py);
      park_log("SetWindowPos", x, y, px, py);
      x = px, y = py;
    }
    flags |= SWP_NOACTIVATE;
  }
  return o_setwindowpos(h, after, x, y, cx, cy, flags);
}
static BOOL WINAPI w_movewindow(void *h, int x, int y, int w, int hh, BOOL repaint) {
  if (parked(h)) {
    int px, py;
    park_xy(&px, &py);
    park_log("MoveWindow", x, y, px, py);
    x = px, y = py;
  }
  return o_movewindow(h, x, y, w, hh, repaint);
}
static BOOL WINAPI w_showwindow(void *h, int cmd) {
  // SW_SHOWNORMAL 1, SHOWMAXIMIZED 3, SHOW 5, RESTORE 9, SHOWDEFAULT 10 -> SHOWNA 8 / SHOWNOACTIVATE 4 (no maximize)
  if (parked(h) && (cmd == 1 || cmd == 3 || cmd == 5 || cmd == 9 || cmd == 10)) cmd = cmd == 5 ? 8 : 4;
  return o_showwindow(h, cmd);
}
static BOOL WINAPI w_setforeground(void *h) {
  (void)h;
  park_log("SetForegroundWindow ignored", 0, 0, -1, -1);
  return 1;
}
static BOOL WINAPI w_clipcursor(const void *r) {
  if (r) park_log("ClipCursor ignored", 0, 0, -1, -1);
  return 1;
}
static BOOL WINAPI w_setcursorpos(int x, int y) {
  park_log("SetCursorPos ignored", x, y, -1, -1);
  return 1;
}

// The crash reporter (0x425435) asks MessageBoxA(NULL, report, "Send crash log?", MB_YESNO | MB_ICONHAND | MB_TOPMOST),
// which would pop up on the user's screen. MessageBoxA is the exe's only message box import. With window_park the box
// is never shown: its caption and text go to the log, and the process ends with MSGBOX_EXIT for hookbisect to read.
#define MSGBOX_EXIT 0xC0DEB0C5u
IMPORT BOOL WINAPI TerminateProcess(HANDLE, u32);
static int WINAPI w_messagebox(void *hwnd, const char *text, const char *caption, u32 type) {
  static char t[2100];  // static: a crash report may come from a nearly full stack
  char *p = scpy(t, "msgbox: "), *end = t + sizeof t - 16;
  (void)hwnd;
  (void)type;
  for (const char *s = caption ? caption : "(none)"; *s && p < end - 1000; s++) *p++ = *s;
  p = scpy(p, " | ");
  for (const char *s = text ? text : "(none)"; *s && p < end; s++)  // one line: CR LF become " / "
    if (*s == '\n') p = scpy(p, " / ");
    else if (*s != '\r') *p++ = *s;
  *p = 0;
  logx(t);
  write_hits();
  TerminateProcess(GetCurrentProcess(), MSGBOX_EXIT);
  return 0;
}

static void setup_park(u8 *exe, char *buf) {
  cfg("window_park", "FF_HYBRID_WINDOW_PARK", "0", buf, VALBUF);
  if (buf[0] != '1') return;
  o_createwindow = (void *(WINAPI *)(DWORD, const char *, const char *, DWORD, int, int, int, int, void *, void *,
                                     void *, void *))iat_hook(exe, "CreateWindowExA", (void *)w_createwindow,
                                                              "window_park");
  o_setwindowpos = (BOOL(WINAPI *)(void *, void *, int, int, int, int, u32))iat_hook(
      exe, "SetWindowPos", (void *)w_setwindowpos, "window_park");
  o_movewindow = (BOOL(WINAPI *)(void *, int, int, int, int, BOOL))iat_hook(exe, "MoveWindow", (void *)w_movewindow,
                                                                             "window_park");
  o_showwindow = (BOOL(WINAPI *)(void *, int))iat_hook(exe, "ShowWindow", (void *)w_showwindow, "window_park");
  iat_hook(exe, "SetForegroundWindow", (void *)w_setforeground, "window_park");
  iat_hook(exe, "ClipCursor", (void *)w_clipcursor, "window_park");
  iat_hook(exe, "SetCursorPos", (void *)w_setcursorpos, "window_park");
  iat_hook(exe, "MessageBoxA", (void *)w_messagebox, "window_park");
  int px, py;
  park_xy(&px, &py);
  char line[80], *p = sint(scpy(line, "window_park: top-level windows at "), px);
  sint(scpy(p, ","), py);
  logl(line, NULL);
  if (!o_createwindow) logl("window_park: the exe does not import CreateWindowExA; the window is NOT parked", NULL);
}

// ---------------------------------------------------------------- profile_dir: a private user folder
// The game's user folder (freedom.ini, Keyboard.cfg, Profiles\*.dat) is SHGetKnownFolderPath(FOLDERID_RoamingAppData)
// made short (GetShortPathNameW, so it must exist) plus "\IO Interactive\Freedom Fighters\" (0x4210cb..0x4211a9; the
// exe has no other call of SHGetKnownFolderPath, and the suffix string at 0x6785ac no other reference).
// profile_dir=<path> makes the folder <path> itself: the RoamingAppData answer becomes <path> and the suffix "\".
// A missing <path>\freedom.ini is first copied from profile_template, so a test instance never reads or writes the
// user's settings or profiles, and instances with their own folders share nothing.
#define SUFFIX_VA 0x6785acu
IMPORT BOOL WINAPI CopyFileA(const char *, const char *, BOOL);
IMPORT DWORD WINAPI GetFileAttributesA(const char *);
IMPORT int WINAPI MultiByteToWideChar(u32, DWORD, const char *, int, u16 *, int);

static const u8 FOLDERID_RoamingAppData[16] = {0xDB, 0x85, 0xB6, 0x3E, 0xF9, 0x65, 0xF6, 0x4C,
                                               0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D};
static HRESULT(WINAPI *o_knownfolder)(const u8 *, DWORD, void *, u16 **);
static void *(WINAPI *p_cotaskmemalloc)(u32);
static u16 g_profile_w[600];
static int g_profile_wn;  // characters with the terminating 0
static char g_profile[600];

static HRESULT WINAPI w_knownfolder(const u8 *rfid, DWORD flags, void *token, u16 **out) {
  int i = 0;
  while (rfid && i < 16 && rfid[i] == FOLDERID_RoamingAppData[i]) i++;
  if (i < 16 || !out) return o_knownfolder(rfid, flags, token, out);
  u16 *w = (u16 *)p_cotaskmemalloc((u32)g_profile_wn * 2);  // the game frees it with CoTaskMemFree
  if (!w) return (HRESULT)0x8007000EL;                     // E_OUTOFMEMORY
  for (i = 0; i < g_profile_wn; i++) w[i] = g_profile_w[i];
  *out = w;
  logx("profile_dir: the game asked for RoamingAppData and got the profile folder");
  return 0;
}

static void profile_fail(const char *msg, u32 code) {  // always fatal: on_error=continue would use the real folder
  g_abort = 1;
  fail(msg, code);
}

static void setup_profile(u8 *exe, char *buf) {
  cfg("profile_dir", "FF_HYBRID_PROFILE_DIR", "", buf, VALBUF);
  if (!buf[0]) return;
  path_in_dir(g_profile, buf);
  char *e = g_profile + slen(g_profile);
  while (e > g_profile + 3 && (e[-1] == '\\' || e[-1] == '/')) *--e = 0;  // the patched suffix adds the "\"
  for (char *q = g_profile + 3; q <= e; q++)  // create every level: GetShortPathNameW needs the folder to exist
    if (*q == '\\' || *q == '/' || !*q) {
      char c = *q;
      *q = 0;
      CreateDirectoryA(g_profile, NULL);
      *q = c;
    }
  g_profile_wn = MultiByteToWideChar(0 /* CP_ACP */, 0, g_profile, -1, g_profile_w, 600);
  HMODULE ole = GetModuleHandleA("ole32.dll");
  p_cotaskmemalloc = (void *(WINAPI *)(u32))(ole ? GetProcAddress(ole, "CoTaskMemAlloc") : NULL);
  static const char suffix[] = "\\IO Interactive\\Freedom Fighters\\";
  char *s = (char *)SUFFIX_VA;
  int same = g_exe_end > SUFFIX_VA + sizeof suffix;
  for (u32 i = 0; same && i < sizeof suffix; i++) same = s[i] == suffix[i];
  DWORD old;
  if (!same || !g_profile_wn || !p_cotaskmemalloc || !VirtualProtect(s, 2, PAGE_READWRITE, &old)) {
    profile_fail("profile_dir: this exe does not build its user folder as expected; refusing to touch the real one", 0);
    return;
  }
  s[1] = 0;  // "\IO Interactive\Freedom Fighters\" -> "\"
  VirtualProtect(s, 2, old, &old);
  o_knownfolder = (HRESULT(WINAPI *)(const u8 *, DWORD, void *, u16 **))iat_hook(
      exe, "SHGetKnownFolderPath", (void *)w_knownfolder, "profile_dir");
  if (!o_knownfolder) {
    profile_fail("profile_dir: the exe does not import SHGetKnownFolderPath", 0);
    return;
  }
  logl("profile_dir: user folder ", g_profile);

  // freedom.ini from the template when the folder has none (the game's own default is full screen)
  char ini[620], tpl[620];
  scpy(scpy(ini, g_profile), "\\freedom.ini");
  if (GetFileAttributesA(ini) != 0xffffffffu) return;
  cfg("profile_template", "FF_HYBRID_PROFILE_TEMPLATE", "", buf, VALBUF);
  if (!buf[0]) {
    logl("profile_dir: no freedom.ini and no profile_template; the game writes its own defaults", NULL);
    return;
  }
  path_in_dir(tpl, buf);
  if (CopyFileA(tpl, ini, 1)) logl("profile_dir: freedom.ini seeded from ", tpl);
  else profile_fail("profile_dir: cannot copy profile_template", GetLastError());
}

static void setup_input(u8 *exe, char *buf) {
  QueryPerformanceFrequency(&g_qpf);
  QueryPerformanceCounter(&g_t0);
  cfg("input_script", "FF_HYBRID_INPUT_SCRIPT", "", buf, VALBUF);
  if (buf[0]) {
    char path[600];
    path_in_dir(path, buf);
    logl("input_script: ", path);
    load_script(path);
    g_input = g_ncmds > 0;
  }
  cfg("input_record", "FF_HYBRID_INPUT_RECORD", "", buf, VALBUF);
  if (buf[0]) {
    char path[600];
    path_in_dir(path, buf);
    g_rec_h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    g_rec = g_rec_h != INVALID_HANDLE_VALUE;
    logl(g_rec ? "input_record: " : "input_record: cannot create ", path);
    if (g_rec) rec_put("# recorded by the hybrid loader (input_record); replay it with input_script\r\n");
  }
  cfg("input_real", "FF_HYBRID_INPUT_REAL", "1", buf, VALBUF);
  g_input_real = buf[0] != '0';
  cfg("keep_active", "FF_HYBRID_KEEP_ACTIVE", g_input ? "1" : "0", buf, VALBUF);
  g_keep_active = buf[0] == '1';
  cfg("keep_active_wndproc", "FF_HYBRID_KEEP_ACTIVE_WNDPROC", "0x421b40", buf, VALBUF);
  const char *q = buf;
  if (!parse_hex(&q, &g_wndproc_target)) g_wndproc_target = 0x421b40;
  cfg("log_scenes", "FF_HYBRID_LOG_SCENES", g_input || g_trace || g_rec ? "1" : "0", buf, VALBUF);
  g_scene_log = buf[0] == '1' || g_rec;  // the recorder anchors to scene loads
  if (g_input || g_rec) {
    make_fwd();
    for (u32 k = 0; k < 11; k++) g_di_vtbl[k] = g_fwd + k * 20;
    for (u32 k = 0; k < 32; k++) g_dev_vtbl[k] = g_fwd + k * 20;
    g_di_vtbl[3] = (void *)di_create_device;
    g_dev_vtbl[7] = (void *)dev_acquire;
    g_dev_vtbl[8] = (void *)dev_unacquire;
    g_dev_vtbl[9] = (void *)dev_state;
    g_dev_vtbl[10] = (void *)dev_data;
    g_dev_vtbl[13] = (void *)dev_coop;
    logl("input: DirectInput keyboard and mouse will be wrapped; script clock = real time x time_scale", NULL);
    o_screen2client = (BOOL(WINAPI *)(void *, int *))iat_hook(exe, "ScreenToClient", (void *)w_screen2client, "input");
  }
  if (g_keep_active)
    o_registerclass = (u16(WINAPI *)(u32 *))iat_hook(exe, "RegisterClassExA", (void *)w_registerclass, "keep_active");
  if (g_scene_log) {
    o_createfile = (void *(WINAPI *)(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE))iat_hook(
        exe, "CreateFileA", (void *)w_createfile, "log_scenes");
    o_fopen = (void *(__cdecl *)(const char *, const char *))iat_hook(exe, "fopen", (void *)w_fopen, "log_scenes");
#ifdef LOG_OPENS
    o_findfirst = (HANDLE(WINAPI *)(const char *, void *))iat_hook(exe, "FindFirstFileA", (void *)w_findfirst,
                                                                  "LOG_OPENS");
#endif
  }
}

// ---------------------------------------------------------------- the hybrid
static void install(void) {
  char *buf = (char *)VirtualAlloc(NULL, VALBUF, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  Range *inc = (Range *)VirtualAlloc(NULL, MAXRANGES * sizeof(Range) * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  Range *exc = inc + MAXRANGES;
  char path[600], line[200], *p;
  u32 size, ninc, nexc;
  if (!buf || !inc) {
    fail("out of memory", GetLastError());
    return;
  }

  cfg("on_error", "FF_HYBRID_ON_ERROR", "abort", buf, VALBUF);
  g_abort = !seq(buf, "continue");

  // time_scale and trace work in every mode, including none (a faster, traced baseline)
  u8 *exe0 = (u8 *)GetModuleHandleA(NULL), *nt0 = exe0 + *(u32 *)(exe0 + 0x3c);
  g_text_lo = (u32)exe0 + *(u32 *)(nt0 + 0xf8 + 12);  // first section (.text): VirtualAddress, VirtualSize
  g_text_hi = g_text_lo + *(u32 *)(nt0 + 0xf8 + 8);
  g_exe_end = (u32)exe0 + *(u32 *)(nt0 + 0x50);  // SizeOfImage
  cfg("fixed_step", "FF_HYBRID_FIXED_STEP", "0", buf, VALBUF);
  for (const char *q = buf; *q >= '0' && *q <= '9' && g_step_ms < 100000; q++)
    g_step_ms = g_step_ms * 10 + (u32)(*q - '0');
  if (g_step_ms > 1000) g_step_ms = 1000;
  if (g_step_ms) {
    u64 f;
    QueryPerformanceFrequency(&f);
    u32 qf = (u32)f;  // 10 MHz on current Windows; the step in ticks without 64-bit division (no CRT)
    g_step_qpc = qf / 1000 * g_step_ms + qf % 1000 * g_step_ms / 1000;
    p = sdec(scpy(line, "fixed_step: "), g_step_ms);
    p = sdec(scpy(p, " ms of game time per Present ("), g_step_qpc);
    logl(line, " QPC ticks); time_scale is ignored");
    if (f >> 32 || !g_step_qpc) {
      logl("fixed_step: unusable QueryPerformanceFrequency, fixed_step off", NULL);
      g_step_ms = 0;
    }
  }
  cfg("time_scale", "FF_HYBRID_TIME_SCALE", "1", buf, VALBUF);
  g_scale_fx = parse_fx(buf);
  if (g_step_ms) {
    logn("fixed_step: imports wrapped: ", wrap_timers(exe0), 0);
  } else if (g_scale_fx && g_scale_fx != 0x10000) {
    logl("time_scale: ", buf);
    logn("time_scale: imports wrapped: ", wrap_timers(exe0), 0);
  }
  cfg("trace", "FF_HYBRID_TRACE", "0", buf, VALBUF);
  g_trace = buf[0] == '1';
  if (g_trace) {
    cfg("max_dumps", "FF_HYBRID_MAX_DUMPS", "4", buf, VALBUF);
    const char *q = buf;
    u32 md = 4;
    if (*q >= '0' && *q <= '9')
      for (md = 0; *q >= '0' && *q <= '9'; q++) md = md * 10 + (u32)(*q - '0');
    g_max_dumps = (int)md;
    load_names();
    mod_range("ntdll.dll", g_ntdll);
    mod_range("kernelbase.dll", g_kbase);
    mod_range("kernel32.dll", g_k32);
    if (AddVectoredExceptionHandler(1, (void *)veh)) logl("trace: crash dump handler installed (first in chain)", NULL);
    else logl("trace: AddVectoredExceptionHandler failed", NULL);
  }
  setup_input(exe0, buf);
  setup_d3d(exe0, buf);
  setup_park(exe0, buf);
  setup_profile(exe0, buf);

  cfg("mode", "FF_HYBRID_MODE", "all", buf, VALBUF);
  int mode = seq(buf, "none") ? 0 : seq(buf, "list") ? 2 : 1;
  logl("mode: ", buf);
  if (!mode) {
    logl("mode=none: no image mapped, original exe runs unchanged", NULL);
    return;
  }
  cfg("allow_unsafe", "FF_HYBRID_ALLOW_UNSAFE", "0", buf, VALBUF);
  int unsafe = buf[0] == '1';
  cfg("verbose", "FF_HYBRID_VERBOSE", "0", buf, VALBUF);
  int verbose = buf[0] == '1';
  ninc = load_list("include", "FF_HYBRID_INCLUDE", "include_file", "FF_HYBRID_INCLUDE_FILE", inc, buf);
  nexc = load_list("exclude", "FF_HYBRID_EXCLUDE", "exclude_file", "FF_HYBRID_EXCLUDE_FILE", exc, buf);
  logn("include ranges: ", ninc, 0);
  logn("exclude ranges: ", nexc, 0);

  // the exe must sit at its preferred base: the ports use absolute addresses
  u8 *exe = (u8 *)GetModuleHandleA(NULL);
  if ((u32)exe != EXE_BASE) {
    fail("Freedom.Exe is not loaded at 0x400000 (run hybrid/patch_exe.py on this copy to clear DYNAMIC_BASE)", (u32)exe);
    return;
  }

  // plan
  cfg("plan", "FF_HYBRID_PLAN", "ff_hooks.bin", buf, VALBUF);
  path_in_dir(path, buf);
  u8 *planf = read_file(path, &size, NULL);
  if (!planf) {
    fail("cannot read the hook plan (ff_hooks.bin)", GetLastError());
    return;
  }
  PlanHeader *ph = (PlanHeader *)planf;
  PlanEntry *pe = (PlanEntry *)(ph + 1);
  if (size < sizeof(PlanHeader) || ph->magic != PLAN_MAGIC || ph->version != PLAN_VERSION ||
      size < sizeof(PlanHeader) + ph->count * sizeof(PlanEntry) || ph->image_base != PORTS_BASE) {
    fail("ff_hooks.bin is damaged or from another plan version", 0);
    return;
  }
  logn("plan entries: ", ph->count, 0);

  // the exe's .text must be the one the plan was made for
  u32 tfnv = fnv(exe + ph->text_rva, ph->text_size);
  if (tfnv != ph->text_fnv) {
    fail("Freedom.Exe .text does not match the plan (different game build, or something already patched it)", tfnv);
    return;
  }

  // ports image at exactly 0x31000000
  u8 *img = (u8 *)VirtualAlloc((void *)PORTS_BASE, ph->image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (img != (u8 *)PORTS_BASE) {
    if (img) VirtualFree(img, 0, MEM_RELEASE);
    fail("address range 0x31000000 for the ports image is already taken", GetLastError());
    return;
  }
  cfg("image", "FF_HYBRID_IMAGE", "ff_ports.bin", buf, VALBUF);
  path_in_dir(path, buf);
  u32 isize = 0;
  HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    isize = GetFileSize(h, NULL);
    CloseHandle(h);
  }
  if (isize != ph->image_size || !read_file(path, &isize, img)) {
    VirtualFree(img, 0, MEM_RELEASE);
    fail("cannot read the ports image (ff_ports.bin) or its size does not match the plan", isize);
    return;
  }
  if (fnv(img, isize) != ph->image_fnv) {
    VirtualFree(img, 0, MEM_RELEASE);
    fail("ff_ports.bin does not match ff_hooks.bin (rebuild both with hybrid/build.sh)", 0);
    return;
  }
  DWORD old;
  // code and data share the image (mini_ld lays out .text, .rodata, .data, .bss in one block)
  if (!VirtualProtect(img, isize, PAGE_EXECUTE_READWRITE, &old)) {
    fail("VirtualProtect on the ports image failed", GetLastError());
    return;
  }
  p = scpy(line, "ports image mapped at ");
  p = shex(p, PORTS_BASE);
  p = scpy(p, ", ");
  p = sdec(p, isize);
  logl(line, " bytes");

  // trace: one stub per plan entry, and a hit counter each
  g_plan = pe;
  g_nplan = ph->count;
  g_isize = isize;
  if (g_trace) {
    g_hits = (volatile u32 *)VirtualAlloc(NULL, ph->count * 4 + 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    g_stubs = (u8 *)VirtualAlloc(NULL, ph->count * STUB + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_hits || !g_stubs) {
      fail("out of memory for trace stubs", GetLastError());
      return;
    }
    p = scpy(line, "trace: stubs at ");
    p = shex(p, (u32)g_stubs);
    p = scpy(p, ", ring of ");
    sdec(p, RING);
    logl(line, " calls");
  }

  // select, then patch .text in one writable window
  u32 applied = 0, by_cfg = 0, by_status = 0, bad = 0;
  u8 *tlo = exe + ph->text_rva, *thi = tlo + ph->text_size;
  if (!VirtualProtect(tlo, ph->text_size, PAGE_EXECUTE_READWRITE, &old)) {
    fail("VirtualProtect on Freedom.Exe .text failed", GetLastError());
    return;
  }
  for (u32 i = 0; i < ph->count; i++) {
    PlanEntry *e = &pe[i];
    int want = mode == 1 ? 1 : in_ranges(e->addr, inc, ninc);
    if (want && nexc && in_ranges(e->addr, exc, nexc)) want = 0;
    if (!want) {
      by_cfg++;
      continue;
    }
    if (!(e->status == ST_OK || (unsafe && (e->status == ST_SHORT || e->status == ST_INTERIOR)))) {
      by_status++;
      continue;
    }
    u8 *at = (u8 *)e->addr;
    if (at < tlo || at + 5 > thi || e->entry < PORTS_BASE || e->entry >= PORTS_BASE + isize) {
      bad++;
      continue;
    }
    u32 target = e->entry;
    if (g_trace) {
      u8 *stub = g_stubs + i * STUB;
      make_stub(stub, e->addr, e->entry, &g_hits[i]);
      target = (u32)stub;
    }
    at[0] = 0xE9;
    u32 rel = target - (e->addr + 5);
    at[1] = (u8)rel;
    at[2] = (u8)(rel >> 8);
    at[3] = (u8)(rel >> 16);
    at[4] = (u8)(rel >> 24);
    applied++;
    if (verbose) {
      p = scpy(line, "hook ");
      p = shex(p, e->addr);
      p = scpy(p, " -> ");
      shex(p, e->entry);
      logl(line, NULL);
    }
  }
  VirtualProtect(tlo, ph->text_size, PAGE_EXECUTE_READ, &old);
  FlushInstructionCache(GetCurrentProcess(), tlo, ph->text_size);
  if (g_stubs) FlushInstructionCache(GetCurrentProcess(), g_stubs, ph->count * STUB);
  logn("hooks applied: ", applied, 0);
  logn("skipped by config: ", by_cfg, 0);
  logn("skipped as unsafe (plan status): ", by_status, 0);
  logn("skipped as out of range: ", bad, 0);
  if (g_trace) {
    // ff_hits.tsv: rewritten every hits_every seconds (a killed game gets no DLL_PROCESS_DETACH), at a crash, at exit
    cfg("hits_every", "FF_HYBRID_HITS_EVERY", "5", buf, VALBUF);
    u32 every = 0;
    for (const char *q = buf; *q >= '0' && *q <= '9'; q++) every = every * 10 + (u32)(*q - '0');
    if (every) CreateThread(NULL, 0, (void *)hits_thread, (void *)every, 0, NULL);
    logn("trace: ff_hits.tsv every (s): ", every, 0);
  }
  // the plan stays mapped: crash dumps and ff_hits.tsv read it
  VirtualFree(inc, 0, MEM_RELEASE);
  VirtualFree(buf, 0, MEM_RELEASE);
}

BOOL WINAPI DllMain(HMODULE self, DWORD reason, void *reserved) {
  (void)self;
  (void)reserved;
  if (reason == 0) {  // DLL_PROCESS_DETACH: a normal exit
    write_hits();
    return 1;
  }
  if (reason != DLL_PROCESS_ATTACH) return 1;
  char exe[520], *slash = exe;
  u32 n = GetModuleFileNameA(NULL, exe, sizeof exe);
  if (!n || n >= sizeof exe) return 1;
  for (char *q = exe; *q; q++)
    if (*q == '\\' || *q == '/') slash = q;
  slash[1] = 0;
  scpy(g_dir, exe);

  // FF_HYBRID_INI points at another ini; default hooks.ini next to the exe
  char alt[520];
  DWORD k = GetEnvironmentVariableA("FF_HYBRID_INI", alt, sizeof alt);
  path_in_dir(g_ini, k && k < sizeof alt ? alt : "hooks.ini");
  char logname[260];
  GetPrivateProfileStringA("hybrid", "log", "ff_hybrid.log", logname, sizeof logname, g_ini);
  path_in_dir(g_logpath, logname);
  path_in_dir(g_hitspath, "ff_hits.tsv");
  scpy(scpy(g_hitstmp, g_hitspath), ".tmp");
  g_log = CreateFileA(g_logpath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  SYSTEMTIME t;
  GetLocalTime(&t);
  char line[120], *p = scpy(line, "FF hybrid loader, ");
  p = sdec(p, t.wYear);
  *p++ = '-';
  p = sdec2(p, t.wMonth);
  *p++ = '-';
  p = sdec2(p, t.wDay);
  *p++ = ' ';
  p = sdec2(p, t.wHour);
  *p++ = ':';
  p = sdec2(p, t.wMinute);
  *p++ = ':';
  sdec2(p, t.wSecond);
  logl(line, NULL);
  logl("ini: ", g_ini);

  install();
  logl("done; the game continues", NULL);
  if (g_log != INVALID_HANDLE_VALUE) {
    CloseHandle(g_log);
    g_log = INVALID_HANDLE_VALUE;
  }
  return 1;
}

// ---------------------------------------------------------------- forwarding to the system dinput8.dll
static void *real(const char *name) {
  if (!g_real) {
    char p[600];
    u32 n = GetSystemDirectoryA(p, 520);  // System32, redirected to SysWOW64 for this 32-bit process
    if (!n || n >= 520) return NULL;
    scpy(p + n, "\\dinput8.dll");
    g_real = LoadLibraryA(p);
    if (!g_real) return NULL;
  }
  return GetProcAddress(g_real, name);
}

#define E_FAIL ((HRESULT)0x80004005L)

HRESULT WINAPI DirectInput8Create(void *hinst, DWORD ver, const void *riid, void **out, void *outer) {
  typedef HRESULT(WINAPI * fn)(void *, DWORD, const void *, void **, void *);
  fn f = (fn)real("DirectInput8Create");
  HRESULT r = f ? f(hinst, ver, riid, out, outer) : E_FAIL;
  if (r >= 0 && (g_input || g_rec) && out && *out) {
    *out = wrap_obj(*out, g_di_vtbl, 0);
    logx("input: IDirectInput8 wrapped");
  }
  return r;
}
HRESULT WINAPI DllCanUnloadNow(void) {
  typedef HRESULT(WINAPI * fn)(void);
  fn f = (fn)real("DllCanUnloadNow");
  return f ? f() : 1;  // S_FALSE
}
HRESULT WINAPI DllGetClassObject(const void *clsid, const void *iid, void **out) {
  typedef HRESULT(WINAPI * fn)(const void *, const void *, void **);
  fn f = (fn)real("DllGetClassObject");
  return f ? f(clsid, iid, out) : E_FAIL;
}
HRESULT WINAPI DllRegisterServer(void) {
  typedef HRESULT(WINAPI * fn)(void);
  fn f = (fn)real("DllRegisterServer");
  return f ? f() : E_FAIL;
}
HRESULT WINAPI DllUnregisterServer(void) {
  typedef HRESULT(WINAPI * fn)(void);
  fn f = (fn)real("DllUnregisterServer");
  return f ? f() : E_FAIL;
}
