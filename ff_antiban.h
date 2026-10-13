// ff_antiban.h — include cái này vào menu hack của mày
// ============================================================
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Gọi 1 lần khi menu .so load xong
void AntiBan_Init();

// Bật/tắt antiban runtime (gắn vào toggle trong menu)
void AntiBan_Enable(bool on);

// Trả về trạng thái hiện tại
bool AntiBan_IsActive();

#ifdef __cplusplus
}
#endif

// ============================================================
//  Cách tích hợp vào menu hack:
//
//  #include "ff_antiban.h"
//
//  // Trong hàm init của menu:
//  AntiBan_Init();
//
//  // Trong ImGui / menu toggle:
//  static bool antiban = true;
//  if (ImGui::Checkbox("Anti Ban", &antiban)) {
//      AntiBan_Enable(antiban);
//  }
// ============================================================
