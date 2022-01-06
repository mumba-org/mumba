// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DWRITE_FONT_PROXY_MESSAGE_FILTER_WIN_H_
#define MUMBA_HOST_APPLICATION_DWRITE_FONT_PROXY_MESSAGE_FILTER_WIN_H_

#include <dwrite.h>
#include <dwrite_2.h>
#include <wrl.h>
#include <set>
#include <utility>
#include <vector>

#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string16.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/dwrite_font_proxy.mojom.h"
#include "core/host/host_message_filter.h"
#include "core/host/host_thread.h"

namespace service_manager {
struct BindSourceInfo;
}

namespace host {

// Implements a message filter that handles the dwrite font proxy messages.
// If DWrite is enabled, calls into the system font collection to obtain
// results. Otherwise, acts as if the system collection contains no fonts.
class CONTENT_EXPORT DWriteFontProxyImpl : public blink::mojom::DWriteFontProxy {
 public:
  DWriteFontProxyImpl();
  ~DWriteFontProxyImpl() override;

  static void Create(
    blink::mojom::DWriteFontProxyRequest request,
    const service_manager::BindSourceInfo& source_info);

  void SetWindowsFontsPathForTesting(base::string16 path);

 protected:
  // blink::mojom::DWriteFontProxy:
  void FindFamily(const base::string16& family_name,
                  FindFamilyCallback callback) override;
  void GetFamilyCount(GetFamilyCountCallback callback) override;
  void GetFamilyNames(uint32_t family_index,
                      GetFamilyNamesCallback callback) override;
  void GetFontFiles(uint32_t family_index,
                    GetFontFilesCallback callback) override;
  void MapCharacters(const base::string16& text,
                     blink::mojom::DWriteFontStylePtr font_style,
                     const base::string16& locale_name,
                     uint32_t reading_direction,
                     const base::string16& base_family_name,
                     MapCharactersCallback callback) override;
  void MatchUniqueFont(const base::string16& unique_font_name,
                       MatchUniqueFontCallback callback) override;
  void GetUniqueFontLookupMode(
      GetUniqueFontLookupModeCallback callback) override;

  void GetUniqueNameLookupTableIfAvailable(
      GetUniqueNameLookupTableIfAvailableCallback callback) override;

  void GetUniqueNameLookupTable(
      GetUniqueNameLookupTableCallback callback) override;

  void FallbackFamilyAndStyleForCodepoint(
      const std::string& base_family_name,
      const std::string& locale_name,
      uint32_t codepoint,
      FallbackFamilyAndStyleForCodepointCallback callback) override;

  void InitializeDirectWrite();

 private:
  bool IsLastResortFallbackFont(uint32_t font_index);
  bool AddFilesForFont(
    std::set<base::string16>* path_set,
    std::set<base::string16>* custom_font_path_set,
    IDWriteFont* font);
  bool AddLocalFile(
    std::set<base::string16>* path_set,
    std::set<base::string16>* custom_font_path_set,
    IDWriteLocalFontFileLoader* local_loader,
    IDWriteFontFile* font_file);

 private:
  enum CustomFontFileLoadingMode { ENABLE, DISABLE, FORCE };
  
  bool direct_write_initialized_ = false;
  
  Microsoft::WRL::ComPtr<IDWriteFontCollection> collection_;
  Microsoft::WRL::ComPtr<IDWriteFactory> factory_;
  Microsoft::WRL::ComPtr<IDWriteFactory2> factory2_;
  Microsoft::WRL::ComPtr<IDWriteFontFallback> font_fallback_;
  base::string16 windows_fonts_path_;
  CustomFontFileLoadingMode custom_font_file_loading_mode_;
  //base::MappedReadOnlyRegion font_unique_name_table_memory_;

  // Temp code to help track down crbug.com/561873
  std::vector<uint32_t> last_resort_fonts_;

  DISALLOW_COPY_AND_ASSIGN(DWriteFontProxyImpl);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_DWRITE_FONT_PROXY_MESSAGE_FILTER_WIN_H_
