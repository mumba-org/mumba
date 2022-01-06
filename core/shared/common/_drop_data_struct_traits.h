// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_COMMON_DROP_DATA_STRUCT_TRAITS_H_
#define CORE_COMMON_DROP_DATA_STRUCT_TRAITS_H_

#include "base/optional.h"
#include "core/shared/common/drop_data.h"
#include "core/shared/common/native_types.mojom-shared.h"

namespace mojo {

using DropDataMetadataUniquePtr = std::unique_ptr<common::DropDataMetadata>;
using DropDataUniquePtr = std::unique_ptr<common::DropData>;

template <>
struct StructTraits<common::mojom::DropDataMetadataDataView,
                    DropDataMetadataUniquePtr> {

  static common::DropDataMetadataKind kind(const DropDataMetadataUniquePtr& metadata) {
    return metadata->kind;
  }

  static const base::string16& mime_type(const DropDataMetadataUniquePtr& metadata) {
    return metadata->mime_type;
  }

  static const base::FilePath& filename(const DropDataMetadataUniquePtr& metadata) {
    return metadata->filename;
  }

  static const GURL& file_system_url(const DropDataMetadataUniquePtr& metadata) {
    return metadata->file_system_url;
  }

  static bool Read(common::mojom::DropDataMetadataDataView data,
                   DropDataMetadataUniquePtr* out);
};


template <>
struct StructTraits<common::mojom::DropDataDataView,
                    DropDataUniquePtr> {
  
  static int view_id(const DropDataUniquePtr& drop_data) {
    return drop_data->view_id;
  }
  static bool did_originate_from_renderer(const DropDataUniquePtr& drop_data) {
    return drop_data->did_originate_from_renderer;
  }
  static const GURL& url(const DropDataUniquePtr& drop_data) {
    return drop_data->url;
  }
  static const base::string16& url_title(const DropDataUniquePtr& drop_data) {
    return drop_data->url_title;
  }
  static const base::string16 download_metadata(const DropDataUniquePtr& drop_data) {
    return drop_data->download_metadata;
  }
  static const std::vector<ui::FileInfo>& filenames(const DropDataUniquePtr& drop_data) {
    return drop_data->filenames;
  }
  static const std::vector<base::string16>& file_mime_types(const DropDataUniquePtr& drop_data) {
    return drop_data->file_mime_types;
  }
  static const base::string16& filesystem_id(const DropDataUniquePtr& drop_data) {
    return drop_data->filesystem_id;
  }
  static const std::vector<common::DropData::FileSystemFileInfo>& file_system_files(const DropDataUniquePtr& drop_data) {
    return drop_data->file_system_files;
  }
  static const base::NullableString16& text(const DropDataUniquePtr& drop_data) {
    return drop_data->text;
  }
  static const base::NullableString16& html(const DropDataUniquePtr& drop_data) {
    return drop_data->html;
  }
  static const GURL& html_base_url(const DropDataUniquePtr& drop_data) {
    return drop_data->html_base_url;
  }
  static const std::string& file_contents(const DropDataUniquePtr& drop_data) {
    return drop_data->file_contents;
  }
  static const GURL& file_contents_source_url(const DropDataUniquePtr& drop_data) {
    return drop_data->file_contents_source_url;
  }
  static const base::FilePath::StringType& file_contents_filename_extension(const DropDataUniquePtr& drop_data) {
    return drop_data->file_contents_filename_extension;
  }
  static const std::string& file_contents_content_disposition(const DropDataUniquePtr& drop_data) {
    return drop_data->file_contents_content_disposition;
  }
  static const std::unordered_map<base::string16, base::string16>& custom_data(const DropDataUniquePtr& drop_data) {
    return drop_data->custom_data;
  }
  static int key_modifiers(const DropDataUniquePtr& drop_data) {
    return drop_data->key_modifiers;
  }

  static bool Read(common::mojom::DropDataDataView data,
                   DropDataUniquePtr* out);
};

}  // namespace mojo

#endif  // CONTENT_COMMON_RENDER_FRAME_METADATA_STRUCT_TRAITS_H_
