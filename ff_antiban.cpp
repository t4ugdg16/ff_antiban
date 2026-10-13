// ============================================================
//  ff_antiban.cpp — Free Fire Antiban Module (ARM64 Android)
//  Chặn toàn bộ detection pipeline từ IL2CPP layer
//
//  Hook targets (từ dump của mày):
//    1. EventLogger::LogReportCheat            → NOP
//    2. EventLogger::LogReportCheatInHistory   → NOP
//    3. EventLogger::LogAndroidApplicationDetection → NOP
//    4. EventLogger::SendEventTypeHackClientFix → NOP
//    5. EventLogger::LogSlopeSlideDownDetection → NOP (speed detect)
//    6. UIInGameScene::ShowHackerDetectedUI    → NOP (popup cheat)
//    7. GameFacade::IsEmulator                 → return false
//    8. GameFacade::NeedffantihackEmulatorCheck → return false
//    9. LobbyServiceConnectionHandler::OnMsgGroup_ShowTeamMateCheating → NOP
//   10. UINavigationUtil::GotoV2AntiHackWindow → NOP
//
//  Tích hợp vào menu hack:
//    extern "C" void AntiBan_Init();   ← gọi khi menu load
//    extern "C" void AntiBan_Enable(bool on);
//    extern "C" bool AntiBan_IsActive();
//
//  Build:
//    $NDK/bin/aarch64-linux-android29-clang++ \
//      -shared -fPIC -O2 -llog \
//      -I./dobby/include ./dobby/libdobby.a \
//      -o ff_antiban.so ff_antiban.cpp
// ============================================================

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <pthread.h>
#include <android/log.h>

// [SỬA] Include Dobby header thay vì khai báo thủ công
#include "dobby.h"

#define TAG "FF_ANTIBAN"
#define LOG(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, TAG, fmt, ##__VA_ARGS__)

// [SỬA] Xóa block extern "C" khai báo DobbyHook — đã có dobby.h

typedef void*       Il2CppObject;
typedef int32_t     Il2CppBool;

// ═══════════════════════════════════════════════════════════════
//  OFFSET TABLE — từ FF_Method_Offsets.csv
// ═══════════════════════════════════════════════════════════════
namespace AC {
    // EventLogger — reporting pipe
    const uintptr_t LogReportCheat                  = 0x6CF16B4;  // (10 params)
    const uintptr_t LogReportCheatInHistory         = 0x6CF20C8;  // (8 params)
    const uintptr_t LogAndroidApplicationDetection  = 0x6CF3528;  // (1 param) — app scan
    const uintptr_t SendEventTypeHackClientFix      = 0x6D077D4;  // (1 param)
    const uintptr_t LogSlopeSlideDownDetection      = 0x6CE311C;  // speed detect
    const uintptr_t SendLogSlopeSlideDownDetection  = 0x6CF8320;
    const uintptr_t ReportFailedLogs                = 0x6CE352C;

    // UIInGameScene — UI kick / popup
    const uintptr_t ShowHackerDetectedUI            = 0x765F6DC;  // (this, type, msg)
    const uintptr_t OnReportCheatClick              = 0x7669E34;

    // GameFacade — emulator & antihack checks
    const uintptr_t GameFacade_IsEmulator           = 0x71D0FBC;  // ()→bool
    const uintptr_t GameFacade_NeedEmulatorCheck    = 0x71D4F88;  // ()→bool

    // LobbyServiceConnectionHandler — server-side cheat notification
    const uintptr_t OnMsgGroup_ShowTeamMateCheating = 0x88FD490;  // (this, msg, ctx)

    // UINavigationUtil — antihack window
    const uintptr_t GotoV2AntiHackWindow            = 0x6BD2C30;

    // UIDebugConsoleController
    const uintptr_t SetAntiHackButton               = 0x398AC1C;
}

// ═══════════════════════════════════════════════════════════════
//  Base address resolver
// ═══════════════════════════════════════════════════════════════
static uintptr_t g_base = 0;

static uintptr_t GetBase() {
    if (g_base) return g_base;
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libil2cpp.so")) {
            sscanf(line, "%lx-", &g_base);
            LOG("base: 0x%lx", g_base);
            break;
        }
    }
    fclose(maps);
    return g_base;
}

static inline void* RVA(uintptr_t rva) {
    return (void*)(GetBase() + rva);
}

// ═══════════════════════════════════════════════════════════════
//  Feature state
// ═══════════════════════════════════════════════════════════════
static volatile bool g_antiban_on = true;

// [SỬA] Guard chống install hooks 2 lần
static bool g_installed = false;

// ═══════════════════════════════════════════════════════════════
//  Original pointers
// ═══════════════════════════════════════════════════════════════
// variadic / multi-param — dùng raw pointer
static void* orig_LogReportCheat                 = nullptr;
static void* orig_LogReportCheatInHistory        = nullptr;
static void* orig_LogAndroidAppDetect            = nullptr;
static void* orig_SendHackClientFix              = nullptr;
static void* orig_LogSlopeDetect                 = nullptr;
static void* orig_SendSlopeDetect                = nullptr;
static void* orig_ReportFailedLogs               = nullptr;
static void* orig_ShowHackerUI                   = nullptr;
static void* orig_OnReportCheatClick             = nullptr;
static void* orig_ShowTeamMateCheating           = nullptr;
static void* orig_GotoAntiHackWindow             = nullptr;

typedef bool (*t_bool_getter)(Il2CppObject*);
static t_bool_getter orig_IsEmulator             = nullptr;
static t_bool_getter orig_NeedEmulatorCheck      = nullptr;

// ═══════════════════════════════════════════════════════════════
//  HOOK IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════

// ── 1. LogReportCheat (10 params) ──────────────────────────────
//    Game gọi cái này để báo cáo cheat lên server
//    → swallow hoàn toàn
static void hook_LogReportCheat(
    Il2CppObject* _this,
    Il2CppObject* p1, Il2CppObject* p2, Il2CppObject* p3,
    Il2CppObject* p4, Il2CppObject* p5, Il2CppObject* p6,
    Il2CppObject* p7, Il2CppObject* p8, Il2CppObject* p9)
{
    if (g_antiban_on) {
        LOG("blocked: LogReportCheat");
        return;
    }
    typedef void (*t_fn)(Il2CppObject*,Il2CppObject*,Il2CppObject*,
                         Il2CppObject*,Il2CppObject*,Il2CppObject*,
                         Il2CppObject*,Il2CppObject*,Il2CppObject*,Il2CppObject*);
    ((t_fn)orig_LogReportCheat)(_this,p1,p2,p3,p4,p5,p6,p7,p8,p9);
}

// ── 2. LogReportCheatInHistory (8 params) ──────────────────────
static void hook_LogReportCheatInHistory(
    Il2CppObject* _this,
    Il2CppObject* p1, Il2CppObject* p2, Il2CppObject* p3,
    Il2CppObject* p4, Il2CppObject* p5, Il2CppObject* p6,
    Il2CppObject* p7)
{
    if (g_antiban_on) {
        LOG("blocked: LogReportCheatInHistory");
        return;
    }
    typedef void (*t_fn)(Il2CppObject*,Il2CppObject*,Il2CppObject*,
                         Il2CppObject*,Il2CppObject*,Il2CppObject*,
                         Il2CppObject*,Il2CppObject*);
    ((t_fn)orig_LogReportCheatInHistory)(_this,p1,p2,p3,p4,p5,p6,p7);
}

// ── 3. LogAndroidApplicationDetection (app scan) ───────────────
//    Scan danh sách app đang chạy → báo server
static void hook_LogAndroidAppDetect(Il2CppObject* _this,
                                     Il2CppObject* appList)
{
    if (g_antiban_on) {
        LOG("blocked: LogAndroidApplicationDetection");
        return;
    }
    typedef void (*t_fn)(Il2CppObject*, Il2CppObject*);
    ((t_fn)orig_LogAndroidAppDetect)(_this, appList);
}

// ── 4. SendEventTypeHackClientFix ──────────────────────────────
static void hook_SendHackClientFix(Il2CppObject* _this,
                                   Il2CppObject* param)
{
    if (g_antiban_on) {
        LOG("blocked: SendEventTypeHackClientFix");
        return;
    }
    typedef void (*t_fn)(Il2CppObject*, Il2CppObject*);
    ((t_fn)orig_SendHackClientFix)(_this, param);
}

// ── 5. LogSlopeSlideDownDetection (speed detect) ───────────────
static void hook_LogSlopeDetect(Il2CppObject* _this,
                                Il2CppObject* data)
{
    if (g_antiban_on) {
        LOG("blocked: LogSlopeSlideDownDetection");
        return;
    }
    typedef void (*t_fn)(Il2CppObject*, Il2CppObject*);
    ((t_fn)orig_LogSlopeDetect)(_this, data);
}

// ── 6. SendLogSlopeSlideDownDetection ──────────────────────────
static void hook_SendSlopeDetect(Il2CppObject* _this) {
    if (g_antiban_on) return;
    typedef void (*t_fn)(Il2CppObject*);
    ((t_fn)orig_SendSlopeDetect)(_this);
}

// ── 7. ReportFailedLogs ────────────────────────────────────────
static void hook_ReportFailedLogs(Il2CppObject* _this) {
    if (g_antiban_on) return;
    typedef void (*t_fn)(Il2CppObject*);
    ((t_fn)orig_ReportFailedLogs)(_this);
}

// ── 8. ShowHackerDetectedUI ────────────────────────────────────
//    Popup "Hack detected" trong game → block
static void hook_ShowHackerUI(Il2CppObject* _this,
                              int           hackType,
                              Il2CppObject* msg)
{
    if (g_antiban_on) {
        LOG("blocked: ShowHackerDetectedUI type=%d", hackType);
        return;
    }
    typedef void (*t_fn)(Il2CppObject*, int, Il2CppObject*);
    ((t_fn)orig_ShowHackerUI)(_this, hackType, msg);
}

// ── 9. OnReportCheatClick ──────────────────────────────────────
static void hook_OnReportCheatClick(Il2CppObject* _this,
                                    Il2CppObject* param)
{
    // Không block cái này — cho phép người chơi khác bấm report
    // nhưng report sẽ bị chặn ở LogReportCheat phía trên
    typedef void (*t_fn)(Il2CppObject*, Il2CppObject*);
    ((t_fn)orig_OnReportCheatClick)(_this, param);
}

// ── 10. OnMsgGroup_ShowTeamMateCheating ────────────────────────
//    Server push notification về teammate cheat → block
static void hook_ShowTeamMateCheating(Il2CppObject* _this,
                                      Il2CppObject* msg,
                                      Il2CppObject* ctx)
{
    if (g_antiban_on) {
        LOG("blocked: ShowTeamMateCheating");
        return;
    }
    typedef void (*t_fn)(Il2CppObject*, Il2CppObject*, Il2CppObject*);
    ((t_fn)orig_ShowTeamMateCheating)(_this, msg, ctx);
}

// ── 11. GotoV2AntiHackWindow ───────────────────────────────────
static void hook_GotoAntiHackWindow(Il2CppObject* _this) {
    if (g_antiban_on) {
        LOG("blocked: GotoV2AntiHackWindow");
        return;
    }
    typedef void (*t_fn)(Il2CppObject*);
    ((t_fn)orig_GotoAntiHackWindow)(_this);
}

// ── 12. IsEmulator → always false ──────────────────────────────
static bool hook_IsEmulator(Il2CppObject* _this) {
    return false;
}

// ── 13. NeedffantihackEmulatorCheck → always false ─────────────
static bool hook_NeedEmulatorCheck(Il2CppObject* _this) {
    return false;
}

// ═══════════════════════════════════════════════════════════════
//  Hook installer
// ═══════════════════════════════════════════════════════════════
#define HOOK(rva, fn, orig_ptr) do { \
    void* addr = RVA(rva); \
    if (DobbyHook(addr, (void*)(fn), (void**)(orig_ptr)) == 0) \
        LOG("OK: " #fn " @ 0x%x", (uint32_t)(rva)); \
    else \
        LOG("FAIL: " #fn " @ 0x%x", (uint32_t)(rva)); \
} while(0)

static bool InstallAntiBanHooks() {
    // [SỬA] Guard chống double-install
    if (g_installed) {
        LOG("already installed, skip");
        return true;
    }

    if (!GetBase()) {
        LOG("ERROR: cannot resolve base");
        return false;
    }

    LOG("installing antiban hooks...");

    // Detection reporting
    HOOK(AC::LogReportCheat,                hook_LogReportCheat,        &orig_LogReportCheat);
    HOOK(AC::LogReportCheatInHistory,       hook_LogReportCheatInHistory, &orig_LogReportCheatInHistory);
    HOOK(AC::LogAndroidApplicationDetection,hook_LogAndroidAppDetect,   &orig_LogAndroidAppDetect);
    HOOK(AC::SendEventTypeHackClientFix,    hook_SendHackClientFix,     &orig_SendHackClientFix);

    // Speed detection
    HOOK(AC::LogSlopeSlideDownDetection,    hook_LogSlopeDetect,        &orig_LogSlopeDetect);
    HOOK(AC::SendLogSlopeSlideDownDetection,hook_SendSlopeDetect,       &orig_SendSlopeDetect);

    // Failed log reporting
    HOOK(AC::ReportFailedLogs,              hook_ReportFailedLogs,      &orig_ReportFailedLogs);

    // UI popups
    HOOK(AC::ShowHackerDetectedUI,          hook_ShowHackerUI,          &orig_ShowHackerUI);
    HOOK(AC::GotoV2AntiHackWindow,          hook_GotoAntiHackWindow,    &orig_GotoAntiHackWindow);

    // Server notification
    HOOK(AC::OnMsgGroup_ShowTeamMateCheating, hook_ShowTeamMateCheating, &orig_ShowTeamMateCheating);

    // Emulator checks → false
    HOOK(AC::GameFacade_IsEmulator,         hook_IsEmulator,            &orig_IsEmulator);
    HOOK(AC::GameFacade_NeedEmulatorCheck,  hook_NeedEmulatorCheck,     &orig_NeedEmulatorCheck);

    // [SỬA] Đánh dấu đã install
    g_installed = true;

    LOG("antiban hooks installed (%d hooks)", 12);
    return true;
}

// ═══════════════════════════════════════════════════════════════
//  Public API — gọi từ menu hack của mày
// ═══════════════════════════════════════════════════════════════
extern "C" {
    // Gọi 1 lần khi menu load
    void AntiBan_Init() {
        InstallAntiBanHooks();
    }

    // Bật/tắt runtime
    void AntiBan_Enable(bool on) {
        g_antiban_on = on;
        LOG("antiban %s", on ? "ON" : "OFF");
    }

    // Check trạng thái
    bool AntiBan_IsActive() {
        return g_antiban_on;
    }
}

// ═══════════════════════════════════════════════════════════════
//  Auto-init khi .so load
// ═══════════════════════════════════════════════════════════════
__attribute__((constructor))
static void on_load() {
    // Delay nhẹ cho game init xong
    struct timespec ts = { 3, 0 };
    nanosleep(&ts, nullptr);
    LOG("ff_antiban.so loaded");
    // [SỬA] Guard chống double-install: nếu menu đã gọi AntiBan_Init()
    // trước constructor này, lần gọi dưới sẽ tự skip.
    InstallAntiBanHooks();
}
