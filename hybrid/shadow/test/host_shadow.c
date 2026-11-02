// host_shadow.c - test host for the shadow probes: a fixed-base exe at 0x400000 that loads dinput8.dll (the shadow
// loader) from its folder and calls three exported functions a few times. test_capture.py probes them, records the
// samples with collector.py and replays them against a correct and a wrong "ports image" (copies of these functions).
typedef unsigned u32;
#define WINAPI __stdcall
__declspec(dllimport) void *WINAPI LoadLibraryA(const char *);
__declspec(dllimport) void WINAPI ExitProcess(unsigned);
__declspec(dllimport) void WINAPI Sleep(u32);
__declspec(dllimport) void *__cdecl malloc(u32);
__declspec(dllimport) int __cdecl wsprintfA(char *, const char *, ...);

int g_out;
char g_buf[128];

// weighted sum, also stored in a global
__declspec(dllexport) __declspec(noinline) int __fastcall sh_sum(const int *a, int n) {
  int s = 0;
  for (int i = 0; i < n; i++) s += a[i] * (i + 1);
  g_out = s;
  return s;
}

// a malloc'd block filled with a pattern (fake heap in the replay)
__declspec(dllexport) __declspec(noinline) int *__fastcall sh_alloc(int n) {
  volatile int *p = (volatile int *)malloc((u32)n * 4);
  for (int i = 0; i < n; i++) p[i] = 0x5a5a0000 + i;
  return (int *)p;
}

// formatted text through a DLL call (compared in the call log)
__declspec(dllexport) __declspec(noinline) void __cdecl sh_fmt(char *out, int v) {
  wsprintfA(out, "v=%d hex=%x s=%s", v, v * 3, "abc");
}

void WINAPI start(void) {
  LoadLibraryA("dinput8.dll");
  static int arr[16];
  for (int i = 0; i < 16; i++) arr[i] = i * 7;
  int acc = 0;
  for (int r = 0; r < 6; r++) {
    arr[r] += r;
    acc += sh_sum(arr, 16);
    int *p = sh_alloc(8 + r);
    acc += p[3];
    char local[64];
    sh_fmt(local, acc);
    sh_fmt(g_buf, acc + 1);
    acc += local[2] + g_buf[3];
    Sleep(150);
  }
  ExitProcess(acc == 0x7fffffff);
}
