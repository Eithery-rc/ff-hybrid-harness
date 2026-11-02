// host.c - test host for the hybrid loader: a fixed-base exe at 0x400000 that loads dinput8.dll from its folder.
// HOST_CASE selects the check; exit code 0 = pass.
//   basic  target() and t2() reach the fake ports (42, and a + 2b + 4c through ECX, EDX, a stack arg, ret 4);
//          DirectInput8Create is forwarded
//   orig   the hooks are off: target() and t2() run their own code
//   qpc4 / qpc1    QueryPerformanceCounter over Sleep(200) reads about 4x / 1x the real interval
//   clock4         CRT clock() over Sleep(300) reads about 4x
//   crash  three hooked calls, then an access violation; a second-chance handler of the host recovers
typedef void *HMODULE;
typedef long HRESULT;
typedef unsigned u32;
typedef unsigned long long u64;
#define WINAPI __stdcall
__declspec(dllimport) HMODULE WINAPI LoadLibraryA(const char *);
__declspec(dllimport) void *WINAPI GetProcAddress(HMODULE, const char *);
__declspec(dllimport) HMODULE WINAPI GetModuleHandleA(const char *);
__declspec(dllimport) void WINAPI ExitProcess(unsigned);
__declspec(dllimport) u32 WINAPI GetEnvironmentVariableA(const char *, char *, u32);
__declspec(dllimport) int WINAPI QueryPerformanceCounter(u64 *);
__declspec(dllimport) int WINAPI QueryPerformanceFrequency(u64 *);
__declspec(dllimport) void WINAPI Sleep(u32);
__declspec(dllimport) void *WINAPI AddVectoredExceptionHandler(u32, void *);
__declspec(dllimport) long __cdecl clock(void);
__declspec(dllimport) unsigned short WINAPI RegisterClassExA(const void *);
__declspec(dllimport) void *WINAPI CreateWindowExA(u32, const char *, const char *, u32, int, int, int, int, void *, void *,
                                                    void *, void *);
__declspec(dllimport) long WINAPI DefWindowProcA(void *, u32, u32, long);
__declspec(dllimport) long WINAPI SendMessageA(void *, u32, u32, long);
__declspec(dllimport) void *WINAPI CreateFileA(const char *, u32, u32, void *, u32, u32, void *);
__declspec(dllimport) int WINAPI CloseHandle(void *);
__declspec(dllimport) u32 WINAPI GetTickCount(void);

// ---- input case: hidden window, keyboard + mouse through the (wrapped) IDirectInput8
static const unsigned char IID_IDirectInput8A[16];  // defined below
static int g_kill, g_inactive;
__declspec(dllexport) long WINAPI host_wndproc(void *h, u32 m, u32 w, long l) {
  if (m == 8) g_kill++;
  if (m == 6 && !(w & 0xffff)) g_inactive++;
  return DefWindowProcA(h, m, w, l);
}
static const unsigned char GUID_SysKeyboard[16] = {0x61, 0x2B, 0x1D, 0x6F, 0xA0, 0xD5, 0xCF, 0x11,
                                                   0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
static const unsigned char GUID_SysMouse[16] = {0x60, 0x2B, 0x1D, 0x6F, 0xA0, 0xD5, 0xCF, 0x11,
                                                0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
static const unsigned char GUID_Key[16] = {0x20, 0x82, 0x72, 0x55, 0x3C, 0xD3, 0xCF, 0x11,
                                           0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
static const unsigned char GUID_XAxis[16] = {0xE0, 0x02, 0x6D, 0xA3, 0xF3, 0xC9, 0xCF, 0x11,
                                             0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
static const unsigned char GUID_YAxis[16] = {0xE1, 0x02, 0x6D, 0xA3, 0xF3, 0xC9, 0xCF, 0x11,
                                             0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
static const unsigned char GUID_ZAxis[16] = {0xE2, 0x02, 0x6D, 0xA3, 0xF3, 0xC9, 0xCF, 0x11,
                                             0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
typedef struct { const void *guid; u32 ofs, type, flags; } ObjFmt;
typedef struct { u32 size, objsize, flags, datasize, nobjs; ObjFmt *objs; } DataFmt;
static ObjFmt kobj[256], mobj[11];
typedef HRESULT(WINAPI *m0)(void *);
typedef HRESULT(WINAPI *m1)(void *, const void *);
typedef HRESULT(WINAPI *m2)(void *, const void *, const void *);
#define SLOT(o, k) ((*(void ***)(o))[k])

static void *window(void) {
  u32 wc[12] = {48, 0, (u32)host_wndproc, 0, 0, (u32)GetModuleHandleA(0), 0, 0, 0, 0, (u32) "ffhost", 0};
  RegisterClassExA(wc);
  return CreateWindowExA(0, "ffhost", "ffhost", 0, 0, 0, 16, 16, 0, 0, GetModuleHandleA(0), 0);
}

static void input_case(HMODULE d) {
  void *hwnd = window();
  typedef HRESULT(WINAPI * create_fn)(void *, unsigned, const void *, void **, void *);
  create_fn cr = (create_fn)GetProcAddress(d, "DirectInput8Create");
  void *di = 0, *kbd = 0, *mouse = 0;
  if (!hwnd || !cr || cr(GetModuleHandleA(0), 0x0800, IID_IDirectInput8A, &di, 0) != 0) ExitProcess(40);
  typedef HRESULT(WINAPI * cd_fn)(void *, const void *, void **, void *);
  if (((cd_fn)SLOT(di, 3))(di, GUID_SysKeyboard, &kbd, 0) != 0) ExitProcess(41);
  for (u32 i = 0; i < 256; i++) kobj[i].guid = GUID_Key, kobj[i].ofs = i, kobj[i].type = 0x8000000Cu | (i << 8);
  DataFmt kf = {24, 16, 2, 256, 256, kobj};
  if (((m1)SLOT(kbd, 11))(kbd, &kf) != 0) ExitProcess(42);
  typedef HRESULT(WINAPI * coop_fn)(void *, void *, u32);
  if (((coop_fn)SLOT(kbd, 13))(kbd, hwnd, 6) != 0) ExitProcess(43);  // the game's NONEXCLUSIVE|FOREGROUND
  u32 prop[5] = {0x14, 0x10, 0, 0, 32};
  if (((m2)SLOT(kbd, 6))(kbd, (const void *)1, prop) != 0) ExitProcess(44);  // DIPROP_BUFFERSIZE
  if (((m0)SLOT(kbd, 7))(kbd) < 0) ExitProcess(45);
  if (((cd_fn)SLOT(di, 3))(di, GUID_SysMouse, &mouse, 0) != 0) ExitProcess(46);
  ObjFmt m[11] = {{GUID_XAxis, 0, 0x00FFFF03u, 0}, {GUID_YAxis, 4, 0x00FFFF03u, 0}, {GUID_ZAxis, 8, 0x80FFFF03u, 0}};
  for (u32 i = 0; i < 8; i++) m[3 + i].ofs = 12 + i, m[3 + i].type = i < 2 ? 0x00FFFF0Cu : 0x80FFFF0Cu;
  for (u32 i = 0; i < 11; i++) mobj[i] = m[i];
  DataFmt mf = {24, 16, 2, 20, 11, mobj};
  if (((m1)SLOT(mouse, 11))(mouse, &mf) != 0) ExitProcess(47);
  if (((coop_fn)SLOT(mouse, 13))(mouse, hwnd, 5) != 0) ExitProcess(48);  // the game's EXCLUSIVE|FOREGROUND
  if (((m0)SLOT(mouse, 7))(mouse) < 0) ExitProcess(49);  // works only because the loader forced BACKGROUND

  // keep_active: these never reach host_wndproc
  SendMessageA(hwnd, 8, 0, 0);
  SendMessageA(hwnd, 6, 0, 0);

  typedef HRESULT(WINAPI * gdd_fn)(void *, u32, void *, u32 *, u32);
  typedef HRESULT(WINAPI * gds_fn)(void *, u32, void *);
  u32 ev[64][2], nev = 0, t0 = GetTickCount(), scene = 0, button = 0;
  int sx = 0, sy = 0;
  while (GetTickCount() - t0 < 1400) {
    u32 buf[32][5], n = 32;
    if (((gdd_fn)SLOT(kbd, 10))(kbd, 20, buf, &n, 0) >= 0)
      for (u32 i = 0; i < n && nev < 64; i++) ev[nev][0] = buf[i][0], ev[nev++][1] = buf[i][1];
    int ms[5] = {0, 0, 0, 0, 0};
    if (((gds_fn)SLOT(mouse, 9))(mouse, 20, ms) >= 0) {
      sx += ms[0], sy += ms[1];
      if (((unsigned char *)ms)[12] & 0x80) button = 1;
    }
    if (!scene && GetTickCount() - t0 >= 600) {  // a scene change, as the game opening Scenes\*.zip
      void *f = CreateFileA("Scenes_Test.ZIP", 0x40000000u, 0, 0, 2, 0x80, 0);
      if (f != (void *)-1) CloseHandle(f);
      scene = 1;
    }
    Sleep(10);
  }
  static const u32 want[6][2] = {{0x01, 0x80}, {0x01, 0}, {0x1C, 0x80}, {0x1C, 0}, {0x1E, 0x80}, {0x1E, 0}};
  if (nev != 6) ExitProcess(50);
  for (u32 i = 0; i < 6; i++)
    if (ev[i][0] != want[i][0] || ev[i][1] != want[i][1]) ExitProcess(51 + i);
  if (sx != 10 || sy != -5) ExitProcess(57);
  if (!button) ExitProcess(58);
  if (g_kill || g_inactive) ExitProcess(59);
  ExitProcess(0);
}

__declspec(dllexport) __declspec(noinline) int target(void) { return 1; }
__declspec(dllexport) __declspec(noinline) int __fastcall t2(int a, int b, int c) { return a * b * c + 7; }

static const unsigned char IID_IDirectInput8A[16] = {0x30, 0x80, 0x79, 0xbf, 0x3a, 0x48, 0xa2, 0x4d,
                                                     0xaa, 0x99, 0x5d, 0x64, 0xed, 0x36, 0x97, 0x00};

static int is(const char *a, const char *b) {
  while (*a && *a == *b) a++, b++;
  return *a == *b;
}

static void recover(void) { ExitProcess(0); }
static long WINAPI host_veh(u32 **ep) {
  if (ep[0][0] != 0xC0000005u) return 0;
  *(u32 *)((char *)ep[1] + 0xb8) = (u32)recover;  // CONTEXT.Eip
  return -1;  // EXCEPTION_CONTINUE_EXECUTION
}

static u32 ratio100(u32 ms) {  // QPC over Sleep(ms), as 100 * measured / real
  u64 f, q1, q2;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&q1);
  Sleep(ms);
  QueryPerformanceCounter(&q2);
  return (u32)(q2 - q1) * 10u / ((u32)f / 1000u * ms / 10u);
}

void WINAPI start(void) {
  char c[32];
  if (!GetEnvironmentVariableA("HOST_CASE", c, sizeof c)) c[0] = 'b', c[1] = 'a', c[2] = 's', c[3] = 'i', c[4] = 'c', c[5] = 0;
  HMODULE d = LoadLibraryA("dinput8.dll");
  if (!d) ExitProcess(10);
  int (*volatile t)(void) = target;
  int(__fastcall *volatile f2)(int, int, int) = t2;
  if (is(c, "basic")) {
    if (t() != 42) ExitProcess(11);
    if (f2(3, 5, 7) != 3 + 2 * 5 + 4 * 7) ExitProcess(13);
    typedef HRESULT(WINAPI * create_fn)(void *, unsigned, const void *, void **, void *);
    create_fn cr = (create_fn)GetProcAddress(d, "DirectInput8Create");
    void **di = 0;
    if (!cr || cr(GetModuleHandleA(0), 0x0800, IID_IDirectInput8A, (void **)&di, 0) != 0 || !di) ExitProcess(12);
    typedef unsigned long(WINAPI * release_fn)(void *);
    ((release_fn)((void **)*di)[2])(di);
    ExitProcess(0);
  }
  if (is(c, "orig")) ExitProcess(t() == 1 && f2(3, 5, 7) == 112 ? 0 : 11);
  if (is(c, "qpc4")) {
    u32 r = ratio100(200);
    ExitProcess(r >= 300 && r <= 600 ? 0 : 20);
  }
  if (is(c, "qpc1")) {
    u32 r = ratio100(200);
    ExitProcess(r >= 80 && r <= 150 ? 0 : 21);
  }
  if (is(c, "clock4")) {
    long c1 = clock();
    Sleep(300);
    long dd = clock() - c1;
    ExitProcess(dd >= 900 && dd <= 1800 ? 0 : 22);
  }
  if (is(c, "input")) input_case(d);
  if (is(c, "focus0")) {  // keep_active off: the window procedure sees losing focus
    void *hwnd = window();
    SendMessageA(hwnd, 8, 0, 0);
    SendMessageA(hwnd, 6, 0, 0);
    ExitProcess(g_kill == 1 && g_inactive == 1 ? 0 : 60);
  }
  if (is(c, "crash")) {
    AddVectoredExceptionHandler(0, (void *)host_veh);  // last in chain: the loader's handler dumps first
    t();
    f2(1, 2, 3);
    t();
    *(volatile int *)0x10 = 1;
    ExitProcess(30);
  }
  ExitProcess(99);
}
