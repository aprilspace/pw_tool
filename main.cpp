// main.cpp — трей-программа для elementclient.exe
//   * по F12 завершает процесс активного окна (освобождает ОЗУ сразу)
//   * раскидывает процессы elementclient.exe по ядрам
//   * иконка в трее, меню: «Раскидывание по ядрам» (по умолчанию выкл),
//     «Убийство по F12» (по умолчанию вкл), «Закрыть программу»
//   * настройки хранятся в ini рядом с exe (pw_tool.exe -> pw_tool.ini)
//
// Максимально лёгкий вариант: без CRT и libstdc++, без кучи, один поток.
// Хук клавиатуры ставится только когда включено убийство по F12.
// Память: рабочее множество обрезается после каждого действия, через 5 с после старта
// и далее раз в 30 с; службы текстового ввода Windows для процесса отключаются.
//
// СБОРКА (одна команда; icon.o лежит рядом с main.cpp и содержит иконку программы):
//   C:\Apps\w64devkit\bin\g++.exe -Os -s -D_UNICODE -DUNICODE main.cpp icon.o -o pw_tool.exe -mwindows -nostartfiles -Wl,-e,tiny_entry,--gc-sections -ffunction-sections -fdata-sections -fno-exceptions -fno-rtti -fno-asynchronous-unwind-tables -fno-stack-protector -fno-ident -fno-tree-loop-distribute-patterns
//
// Без ini (если захочется ещё меньше кода): добавить -DUSE_INI=0

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>

#ifndef USE_INI
#define USE_INI 1
#endif

// ===================== Настройки =====================
static const wchar_t* const TARGET_EXE = L"elementclient.exe";
static const unsigned char  CORES[]    = { 0, 1, 2, 3 };   // ядра для клиентов
static const UINT           AFFINITY_MS = 12000;           // как часто искать новые окна, мс
static const DWORD          KILL_VK     = VK_F12;          // клавиша убийства активного окна
#define MAX_CLIENTS 32
#define NUM_CORES   ((int)sizeof(CORES))

// Эти процессы не трогаем, даже если они в фокусе
// (клик по рабочему столу/панели задач = фокус у explorer.exe)
static const wchar_t* const PROTECTED_EXE[] = {
    L"explorer.exe", L"dwm.exe", L"winlogon.exe", L"csrss.exe",
    L"wininit.exe",  L"services.exe", L"lsass.exe", L"smss.exe"
};
// =====================================================

#define WM_KILL      (WM_APP + 0)      // хук -> окно: убить PID из wParam
#define WM_TRAY      (WM_APP + 1)      // сообщения от значка в трее
#define ID_AFFINITY  1
#define ID_KILL      2
#define ID_EXIT      3
#define TIMER_AFF    1
#define TIMER_TRIM   2
// Периодическая обрезка рабочего множества. Сразу после старта Windows ещё доинициализирует
// службы текстового ввода уже ПОСЛЕ первой обрезки, поэтому первый раз чистим через
// несколько секунд, дальше раз в полминуты.
#define TRIM_FIRST_MS  5000
#define TRIM_EVERY_MS  30000

static HINSTANCE g_hInst;
static HWND      g_hwnd;
static HICON     g_hIcon;
static HHOOK     g_hook;
static UINT      g_msgTaskbar;
static bool      g_affOn   = false;    // раскидывание: по умолчанию выкл
static bool      g_killOn  = true;     // убийство по F12: по умолчанию вкл
static bool      g_keyDown;
static bool      g_trimLong;           // таймер обрезки уже переведён на редкий интервал
static DWORD     g_lastEvent;
static DWORD     g_pid[MAX_CLIENTS];   // PID -> индекс ядра (раздача не «плывёт»)
static unsigned char g_core[MAX_CLIENTS];
static int       g_n;
static WNDCLASSW        g_wc;          // глобальные: нулевая инициализация без memset
static NOTIFYICONDATAW  g_nid;
#if USE_INI
static wchar_t   g_ini[MAX_PATH + 8];
#endif

// ---------- мелкие помощники вместо CRT ----------
static wchar_t LowerW(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
}

static bool EqNoCase(const wchar_t* a, const wchar_t* b) {
    while (*a && LowerW(*a) == LowerW(*b)) { ++a; ++b; }
    return LowerW(*a) == LowerW(*b);
}

static void Trim() {
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
}

static void* Proc(HMODULE m, const char* name) {
    return (void*)GetProcAddress(m, name);
}

// ---------- права администратора ----------
// Нужны, если игра запущена от админа: иначе хук не получает F12 из её окна,
// а TerminateProcess получает отказ. shell32/advapi32 грузим на момент проверки,
// а не линкуем статически: в обычной работе они в памяти процесса не висят.
typedef BOOL      (WINAPI *OpenProcessTokenFn)(HANDLE, DWORD, PHANDLE);
typedef BOOL      (WINAPI *GetTokenInformationFn)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef HINSTANCE (WINAPI *ShellExecuteWFn)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
typedef BOOL      (WINAPI *ShellNotifyIconWFn)(DWORD, PNOTIFYICONDATAW);

static bool IsElevated() {
    bool res = true;   // не смогли определить: считаем, что всё ок (чтобы не зациклить перезапуск)
    HMODULE adv = LoadLibraryW(L"advapi32.dll");
    if (adv) {
        OpenProcessTokenFn    op = reinterpret_cast<OpenProcessTokenFn>(Proc(adv, "OpenProcessToken"));
        GetTokenInformationFn gt = reinterpret_cast<GetTokenInformationFn>(Proc(adv, "GetTokenInformation"));
        HANDLE tok = NULL;
        if (op && gt && op(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            TOKEN_ELEVATION e;
            DWORD sz = 0;
            e.TokenIsElevated = 0;
            if (gt(tok, TokenElevation, &e, sizeof(e), &sz)) res = (e.TokenIsElevated != 0);
            CloseHandle(tok);
        }
        FreeLibrary(adv);
    }
    return res;
}

static void RelaunchElevated() {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    HMODULE sh = LoadLibraryW(L"shell32.dll");
    if (!sh) return;
    ShellExecuteWFn fn = reinterpret_cast<ShellExecuteWFn>(Proc(sh, "ShellExecuteW"));
    if (fn) {
        HINSTANCE r = fn(NULL, L"runas", path, NULL, NULL, SW_HIDE);
        if ((INT_PTR)r > 32) ExitProcess(0);   // админский экземпляр запущен, этот закрываем
    }
    FreeLibrary(sh);                           // отказ в UAC: работаем без админа
}

// ---------- ini ----------
#if USE_INI
static void InitIniPath() {
    DWORD n = GetModuleFileNameW(NULL, g_ini, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) { g_ini[0] = 0; return; }
    wchar_t* dot = NULL;
    for (wchar_t* p = g_ini; *p; ++p) {
        if (*p == L'\\') dot = NULL;
        else if (*p == L'.') dot = p;
    }
    if (!dot) dot = g_ini + n;
    dot[0] = L'.'; dot[1] = L'i'; dot[2] = L'n'; dot[3] = L'i'; dot[4] = 0;
}

static void LoadIni() {
    if (!g_ini[0]) return;
    g_affOn  = GetPrivateProfileIntW(L"main", L"affinity", 0, g_ini) != 0;
    g_killOn = GetPrivateProfileIntW(L"main", L"kill",     1, g_ini) != 0;
}

static void SaveIni() {
    if (!g_ini[0]) return;
    WritePrivateProfileStringW(L"main", L"affinity", g_affOn  ? L"1" : L"0", g_ini);
    WritePrivateProfileStringW(L"main", L"kill",     g_killOn ? L"1" : L"0", g_ini);
}
#else
static void InitIniPath() {}
static void LoadIni()     {}
static void SaveIni()     {}
#endif

// ---------- убийство ----------
static bool IsProtected(HANDLE h) {
    wchar_t path[MAX_PATH];
    DWORD sz = MAX_PATH;
    if (!QueryFullProcessImageNameW(h, 0, path, &sz)) return true;   // не опознали: не трогаем
    const wchar_t* name = path;
    for (const wchar_t* p = path; *p; ++p)
        if (*p == L'\\') name = p + 1;
    for (int i = 0; i < (int)(sizeof(PROTECTED_EXE) / sizeof(PROTECTED_EXE[0])); ++i)
        if (EqNoCase(name, PROTECTED_EXE[i])) return true;
    return false;
}

static void KillPid(DWORD pid) {
    if (!pid || pid == GetCurrentProcessId()) return;
    HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    if (!IsProtected(h)) TerminateProcess(h, 1);
    CloseHandle(h);
}

// ---------- раскидывание по ядрам ----------
// Возвращает число найденных клиентов или -1, если не удалось получить список процессов.
static int FindTargets(DWORD* out) {
    int m = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (m < MAX_CLIENTS && EqNoCase(pe.szExeFile, TARGET_EXE))
                out[m++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return m;
}

static void UpdateAffinity() {
    DWORD cur[MAX_CLIENTS];
    int m = FindTargets(cur);
    if (m < 0) return;

    // Забываем закрытые процессы
    int k = 0;
    for (int i = 0; i < g_n; ++i) {
        bool alive = false;
        for (int j = 0; j < m; ++j)
            if (cur[j] == g_pid[i]) { alive = true; break; }
        if (alive) { g_pid[k] = g_pid[i]; g_core[k] = g_core[i]; ++k; }
    }
    g_n = k;

    for (int j = 0; j < m; ++j) {
        int idx = -1;
        for (int i = 0; i < g_n; ++i)
            if (g_pid[i] == cur[j]) { idx = g_core[i]; break; }

        if (idx < 0) {   // новый клиент: на самое свободное ядро, уже расставленных не двигаем
            int load[NUM_CORES];
            for (int c = 0; c < NUM_CORES; ++c) load[c] = 0;
            for (int i = 0; i < g_n; ++i) load[g_core[i]]++;
            idx = 0;
            for (int c = 1; c < NUM_CORES; ++c)
                if (load[c] < load[idx]) idx = c;
            if (g_n < MAX_CLIENTS) {
                g_pid[g_n]  = cur[j];
                g_core[g_n] = (unsigned char)idx;
                ++g_n;
            }
        }

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
                               FALSE, cur[j]);
        if (h) {
            DWORD_PTR a = 0, s = 0;
            DWORD_PTR mask = (DWORD_PTR)1 << CORES[idx];
            if (GetProcessAffinityMask(h, &a, &s) && (s & mask) && a != mask)
                SetProcessAffinityMask(h, mask);
            CloseHandle(h);
        }
    }
}

// Снимает привязку: клиенты снова могут работать на любых ядрах.
static void ReleaseAffinity() {
    DWORD cur[MAX_CLIENTS];
    int m = FindTargets(cur);
    for (int j = 0; j < m; ++j) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
                               FALSE, cur[j]);
        if (h) {
            DWORD_PTR a = 0, s = 0;
            if (GetProcessAffinityMask(h, &a, &s) && a != s)
                SetProcessAffinityMask(h, s);
            CloseHandle(h);
        }
    }
    g_n = 0;
}

static void SetAffinityOn(bool on) {
    if (on) {
        g_affOn = true;
        UpdateAffinity();
        SetTimer(g_hwnd, TIMER_AFF, AFFINITY_MS, NULL);
    } else {
        KillTimer(g_hwnd, TIMER_AFF);
        ReleaseAffinity();
        g_affOn = false;
    }
}

// ---------- хук клавиатуры ----------
// Только снимает PID активного окна и отправляет сообщение своему окну: возвращается
// мгновенно, поэтому Windows не отключает хук по таймауту. Убийство идёт уже в WndProc.
static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        const KBDLLHOOKSTRUCT* k = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if (k->vkCode == KILL_VK && !(k->flags & LLKHF_INJECTED)) {
            if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                DWORD now = GetTickCount();
                // Автоповтор при удержании не считаем новым нажатием (иначе после смерти
                // одного окна убьётся следующее). Таймаут — на случай потерянного keyup.
                bool repeat = g_keyDown && (DWORD)(now - g_lastEvent) < 1500;
                g_lastEvent = now;
                g_keyDown   = true;
                if (!repeat) {
                    DWORD pid = 0;
                    HWND w = GetForegroundWindow();   // PID снимаем в момент нажатия
                    if (w) GetWindowThreadProcessId(w, &pid);
                    if (pid) PostMessageW(g_hwnd, WM_KILL, (WPARAM)pid, 0);
                }
            } else {
                g_keyDown = false;
            }
            return 1;   // F12 дальше в систему/игру не пускаем
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Хук ставится только при включённом убийстве: пока выключено, нажатия клавиш
// вообще не проходят через эту программу.
static void SetKillOn(bool on) {
    if (on) {
        if (!g_hook)
            g_hook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, GetModuleHandleW(NULL), 0);
        g_killOn = (g_hook != NULL);
    } else {
        if (g_hook) { UnhookWindowsHookEx(g_hook); g_hook = NULL; }
        g_keyDown = false;
        g_killOn  = false;
    }
}

// ---------- значок в трее ----------
// shell32 грузим только на время вызова Shell_NotifyIconW и сразу выгружаем:
// значок регистрируется в Проводнике, сообщения от него приходят в наше окно сами.
static void TrayNotify(DWORD cmd) {
    HMODULE sh = LoadLibraryW(L"shell32.dll");
    if (!sh) return;
    ShellNotifyIconWFn fn = reinterpret_cast<ShellNotifyIconWFn>(Proc(sh, "Shell_NotifyIconW"));
    if (fn) fn(cmd, &g_nid);
    FreeLibrary(sh);
}

static void ShowMenu(HWND h) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU m = CreatePopupMenu();
    if (!m) return;
    AppendMenuW(m, MF_STRING | (g_affOn  ? MF_CHECKED : 0), ID_AFFINITY, L"Раскидывание по ядрам");
    AppendMenuW(m, MF_STRING | (g_killOn ? MF_CHECKED : 0), ID_KILL,     L"Убийство по F12");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, ID_EXIT, L"Закрыть программу");

    SetForegroundWindow(h);   // без этого меню не закрывается кликом мимо
    int cmd = (int)TrackPopupMenu(m, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                                  pt.x, pt.y, 0, h, NULL);
    PostMessageW(h, WM_NULL, 0, 0);
    DestroyMenu(m);

    if (cmd == ID_AFFINITY) {
        SetAffinityOn(!g_affOn);
        SaveIni();
    } else if (cmd == ID_KILL) {
        SetKillOn(!g_killOn);
        SaveIni();
    } else if (cmd == ID_EXIT) {
        TrayNotify(NIM_DELETE);
        DestroyWindow(h);
    }
    Trim();
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (g_msgTaskbar && m == g_msgTaskbar) {   // Проводник перезапустился: вернуть значок
        TrayNotify(NIM_ADD);
        Trim();
        return 0;
    }
    switch (m) {
    case WM_TRAY:
        if (l == WM_RBUTTONUP || l == WM_LBUTTONUP) ShowMenu(h);
        return 0;
    case WM_KILL:
        if (g_killOn) KillPid((DWORD)w);
        Trim();
        return 0;
    case WM_TIMER:
        if (w == TIMER_AFF) {
            if (g_affOn) UpdateAffinity();
        } else if (w == TIMER_TRIM && !g_trimLong) {
            g_trimLong = true;                          // после первой обрезки переходим на редкий интервал
            SetTimer(h, TIMER_TRIM, TRIM_EVERY_MS, NULL);
        }
        Trim();
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

// Windows цепляет к любому процессу с окном службы текстового ввода (MSCTF, textinputframework,
// CoreMessaging, combase и т.д.) — это сотни КБ, а нашему окну ввод текста не нужен.
// Функции недокументированные, поэтому берём их динамически; нет функции — просто пропускаем.
typedef BOOL (WINAPI *ImmDisableFn)(DWORD);

static void DisableTextServices() {
    HMODULE imm = LoadLibraryW(L"imm32.dll");   // у GUI-процесса она и так загружена; не выгружаем
    if (!imm) return;
    ImmDisableFn tfs = reinterpret_cast<ImmDisableFn>(Proc(imm, "ImmDisableTextFrameService"));
    ImmDisableFn ime = reinterpret_cast<ImmDisableFn>(Proc(imm, "ImmDisableIME"));
    if (tfs) tfs((DWORD)-1);
    if (ime) ime((DWORD)-1);
}

static void Run() {
    if (!IsElevated()) RelaunchElevated();

    // Один экземпляр: два хука = два убийства за одно нажатие
    HANDLE mtx = CreateMutexW(NULL, FALSE, L"Local\\pw_tool_affinity_killer");
    if (!mtx || GetLastError() == ERROR_ALREADY_EXISTS) ExitProcess(0);

    DisableTextServices();   // до создания окна, пока поток ещё не подключён к службам ввода
    g_hInst = GetModuleHandleW(NULL);
    InitIniPath();
    LoadIni();

    // Поток хука должен получать CPU даже когда клиенты грузят процессор на 100%
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    g_msgTaskbar = RegisterWindowMessageW(L"TaskbarCreated");

    g_wc.lpfnWndProc   = WndProc;
    g_wc.hInstance     = g_hInst;
    g_wc.lpszClassName = L"pw_tool_wnd";
    RegisterClassW(&g_wc);
    g_hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, L"pw_tool_wnd", L"pw_tool", WS_POPUP,
                             0, 0, 0, 0, NULL, NULL, g_hInst, NULL);
    if (!g_hwnd) {
        MessageBoxW(NULL, L"Не удалось создать окно.", L"pw_tool", MB_ICONERROR);
        ExitProcess(1);
    }
    // Программа работает от админа: без этого сообщение о перезапуске Проводника не дойдёт
    if (g_msgTaskbar) ChangeWindowMessageFilterEx(g_hwnd, g_msgTaskbar, MSGFLT_ALLOW, NULL);

    // Иконка из ресурсов exe (icon.o); если её нет, стандартная
    int sm = GetSystemMetrics(SM_CXSMICON);
    g_hIcon = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, sm, sm, LR_DEFAULTCOLOR);
    if (!g_hIcon) g_hIcon = LoadIconW(NULL, IDI_APPLICATION);

    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = g_hwnd;
    g_nid.uID              = 1;
    g_nid.uFlags           = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon            = g_hIcon;
    {
        const wchar_t* tip = L"pw_tool";
        for (int i = 0; i < (int)(sizeof(g_nid.szTip) / sizeof(g_nid.szTip[0])) - 1 && tip[i]; ++i)
            g_nid.szTip[i] = tip[i];
    }
    TrayNotify(NIM_ADD);

    // Применяем сохранённые (или стандартные) настройки
    bool wantKill = g_killOn, wantAff = g_affOn;
    g_killOn = false;
    g_affOn  = false;
    if (wantKill) {
        SetKillOn(true);
        if (!g_killOn)
            MessageBoxW(NULL, L"Не удалось установить хук клавиатуры. Убийство по F12 выключено.",
                        L"pw_tool", MB_ICONERROR);
    }
    if (wantAff) SetAffinityOn(true);
    SetTimer(g_hwnd, TIMER_TRIM, TRIM_FIRST_MS, NULL);   // отложенная обрезка памяти, см. выше
    Trim();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
        DispatchMessageW(&msg);

    SetKillOn(false);
    if (g_affOn) ReleaseAffinity();   // при выходе клиенты снова свободны
    ExitProcess(0);
}

// Лёгкий вход (используется с -nostartfiles -Wl,-e,tiny_entry)
extern "C" void tiny_entry() {
    Run();
    ExitProcess(0);
}

// Обычный вход (если собрать без -nostartfiles, например прежней командой)
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    Run();
    return 0;
}
