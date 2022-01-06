// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_COMMON_SCREEN_STRUCT_TRAITS_H_
#define CORE_COMMON_SCREEN_STRUCT_TRAITS_H_

#include "core/common/application.mojom-shared.h"
#include "core/common/screen_info.h"
#include "core/common/screen_orientation_values.h"
#include "core/common/drop_data.h"
#include "core/common/drag_event_source_info.h"

namespace mojo {

template <>
struct StructTraits<common::mojom::ScreenInfoDataView, common::ScreenInfo> {
  
  static float device_scale_factor(const common::ScreenInfo& info) {
    return info.device_scale_factor;
  }
  
  static gfx::ColorSpace color_space(const common::ScreenInfo& info){
    return info.color_space;
  }
  
  static uint32 depth(const common::ScreenInfo& info){
    return info.depth;
  }
  
  static uint32 depth_per_component(const common::ScreenInfo& info){
    return info.depth_per_component;
  }
  
  static bool is_monochrome(const common::ScreenInfo& info){
    return info.is_monochrome;
  }
  
  static gfx::Rect rect(const common::ScreenInfo& info){
    return info.rect;
  }
  
  static gfx::Rect available_rect(const common::ScreenInfo& info){
    return info.available_rect;
  }
  
  static common::ScreenOrientationValues orientation_type(const common::ScreenInfo& info){
    return info.orientation_type;
  }
  
  static uint16 orientation_angle(const common::ScreenInfo& info) {
    return info.orientation_angle;
  }
  
  static bool Read(common::mojom::ScreenInfoDataView data, common::ScreenInfo* out) {
    out->device_scale_factor = data.device_scale_factor();
    out->color_space = data.color_space();
    out->depth = data.depth();
    out->depth_per_component = data.depth_per_component();
    out->is_monochrome = data.is_monochrome();
    out->rect = data.rect();
    out->available_rect = data.available_rect();
    out->orientation_type = data.orientation_type();
    out->orientation_angle = data.orientation_angle();
    
    return true;
  }
};

template <>
struct EnumTraits<common::mojom::ScreenOrientationValues, common::ScreenOrientationValues> {
  static common::mojom::ScreenOrientationValues ToMojom(common::ScreenOrientationValues orientation) {
    switch (orientation) {
      case common::SCREEN_ORIENTATION_VALUES_DEFAULT:
        return common::mojom::ScreenOrientationValues::DEFAULT;
      case common::SCREEN_ORIENTATION_VALUES_PORTRAIT_PRIMARY:
        return common::mojom::ScreenOrientationValues::PORTRAIT_PRIMARY;
      case common::SCREEN_ORIENTATION_VALUES_PORTRAIT_SECONDARY:
        return common::mojom::ScreenOrientationValues::PORTRAIT_SECONDARY;
      case common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_PRIMARY:
        return common::mojom::ScreenOrientationValues::LANDSCAPE_PRIMARY;
      case common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_SECONDARY:
        return common::mojom::ScreenOrientationValues::LANDSCAPE_SECONDARY;
      case common::SCREEN_ORIENTATION_VALUES_ANY:
        return common::mojom::ScreenOrientationValues::ANY;
      case common::SCREEN_ORIENTATION_VALUES_LANDSCAPE:
        return common::mojom::ScreenOrientationValues::LANDSCAPE;
      case common::SCREEN_ORIENTATION_VALUES_PORTRAIT:
        return common::mojom::ScreenOrientationValues::PORTRAIT;
      case common::SCREEN_ORIENTATION_VALUES_NATURAL:
        return common::mojom::ScreenOrientationValues::NATURAL;
      default:
        NOTREACHED();
        return common::mojom::ScreenOrientationValues::DEFAULT;
    }
  }

  static bool FromMojom(common::mojom::ScreenOrientationValues orientation, common::ScreenOrientationValues* out) {
    switch (orientation) {
      case common::mojom::ScreenOrientationValues::DEFAULT:
        *out = common::SCREEN_ORIENTATION_VALUES_DEFAULT;
        return true;
      case common::mojom::ScreenOrientationValues::PORTRAIT_PRIMARY:
        *out = common::SCREEN_ORIENTATION_VALUES_PORTRAIT_PRIMARY;
        return true;
      case common::mojom::ScreenOrientationValues::PORTRAIT_SECONDARY:
        *out = common::SCREEN_ORIENTATION_VALUES_PORTRAIT_SECONDARY;
        return true;
      case common::mojom::ScreenOrientationValues::LANDSCAPE_PRIMARY:
        *out = common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_PRIMARY;
        return true;
      case common::mojom::ScreenOrientationValues::LANDSCAPE_SECONDARY:
        *out = common::SCREEN_ORIENTATION_VALUES_LANDSCAPE_SECONDARY;
        return true;
      case common::mojom::ScreenOrientationValues::ANY:
        *out = common::SCREEN_ORIENTATION_VALUES_ANY;
        return true;
      case common::mojom::ScreenOrientationValues::LANDSCAPE:
        *out = common::SCREEN_ORIENTATION_VALUES_LANDSCAPE;
        return true;
      case common::mojom::ScreenOrientationValues::PORTRAIT:
        *out = common::SCREEN_ORIENTATION_VALUES_PORTRAIT;
        return true;
      default:
        NOTREACHED();
        return false;
    }
  }
};

template <>
struct StructTraits<common::mojom::DropData, common::DropData> {

  int view_id = MSG_ROUTING_NONE;
  bool did_originate_from_renderer;
  GURL url;
  base::string16 url_title;  // The title associated with |url|.
  base::string16 download_metadata;
  std::vector<ui::FileInfo> filenames;
  std::vector<base::string16> file_mime_types;
  base::string16 filesystem_id;
  std::vector<FileSystemFileInfo> file_system_files;
  base::NullableString16 text;
  base::NullableString16 html;
  GURL html_base_url;
  std::string file_contents;
  GURL file_contents_source_url;
  base::FilePath::StringType file_contents_filename_extension;
  std::string file_contents_content_disposition;
  std::unordered_map<base::string16, base::string16> custom_data;
  int key_modifiers;
  
  static int key_modifiers(const common::DropData& drop_data) {
    return drop_data.key_modifiers;
  }

  static GURL url(const common::DropData& drop_data) {
    return drop_data.url;
  }

  static base::string16 url_title(const common::DropData& drop_data) {
    return drop_data.url_title;
  }
  
  static base::string16 download_metadata(const common::DropData& drop_data) {
    return drop_data.download_metadata;
  }
  
  static filenames(const common::DropData& drop_data) {
    return drop_data.filenames;
  }

  static filesystem_id(const common::DropData& drop_data) {
    return drop_data.filesystem_id;
  }

  static file_system_files(const common::DropData& drop_data) {
    return drop_data.file_system_files;
  }

  static text(const common::DropData& drop_data) {
    return drop_data.text;
  }
  
  static html(const common::DropData& drop_data) {
    return drop_data.html;
  }
  
  static html_base_url(const common::DropData& drop_data) {
    return drop_data.html_base_url;
  }
  
  static file_contents(const common::DropData& drop_data) {
    return drop_data.file_contents;
  }
  
  static file_contents_source_url(const common::DropData& drop_data) {
    return drop_data.file_contents_source_url;
  }

  static file_contents_filename_extension(const common::DropData& drop_data) {
    return drop_data.file_contents_filename_extension;
  }
  
  static file_contents_content_disposition(const common::DropData& drop_data) {
    return drop_data.file_contents_content_disposition;
  }

  static std::unordered_map<base::string16, base::string16> custom_data(const common::DropData& drop_data) {
    return drop_data.custom_data;
  }
  
  static bool Read(common::mojom::DropData data, common::DropData* out) {
    
    out->key_modifiers = data.key_modifiers();
    out->url = data.url();
    out->url_title = data.url_title();
    out->download_metadata = data.download_metadata();
    out->filenames = data.filenames();
    out->filesystem_id = data.filesystem_id();
    out->file_system_files = data.file_system_files();
    out->text = data.text();
    out->html = data.html();
    out->html_base_url = data.html_base_url();
    out->file_contents = data.file_contents();
    out->file_contents_source_url = data.file_contents_source_url();
    out->file_contents_filename_extension = data.file_contents_filename_extension();
    out->file_contents_content_disposition = data.file_contents_content_disposition();
    out->custom_data = data.custom_data();
    
    return true;
  }
};

GURL url;
    int64_t size = 0;
    std::string filesystem_id;

IPC_STRUCT_TRAITS_BEGIN(content::DropData::FileSystemFileInfo)
  IPC_STRUCT_TRAITS_MEMBER(url)
  IPC_STRUCT_TRAITS_MEMBER(size)
  IPC_STRUCT_TRAITS_MEMBER(filesystem_id)
IPC_STRUCT_TRAITS_END()

Kind kind;
base::string16 mime_type;
base::FilePath filename;
GURL file_system_url;

IPC_STRUCT_TRAITS_BEGIN(content::DropData::Metadata)
  IPC_STRUCT_TRAITS_MEMBER(kind)
  IPC_STRUCT_TRAITS_MEMBER(mime_type)
  IPC_STRUCT_TRAITS_MEMBER(filename)
  IPC_STRUCT_TRAITS_MEMBER(file_system_url)
IPC_STRUCT_TRAITS_END()

template <>
struct StructTraits<common::mojom::DragEventSourceInfo, common::DragEventSourceInfo> {
  
  static gfx::Point event_location(const common::DragEventSourceInfo& event_source) {
    return event_source.event_location;
  }

  static ui::DragDropTypes::DragEventSource event_source(const common::DragEventSourceInfo& event_source) {
    return event_source.event_source;
  }

  static bool Read(common::mojom::DragEventSourceInfo event_source, common::DragEventSourceInfo* out) {
    out->event_location = event_source.event_location();
    out->event_source = event_source.event_source();
    return true;
  }
};


}  // namespace mojo

#endif  // CORE_COMMON_SCREEN_STRUCT_TRAITS_H_
