// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/drop_data_struct_traits.h"

//#include "services/viz/public/cpp/compositing/selection_struct_traits.h"
//#include "ui/gfx/geometry/mojo/geometry_struct_traits.h"
//#include "ui/gfx/mojo/selection_bound_struct_traits.h"

namespace mojo {

// static
bool StructTraits<common::mojom::DropDataMetadataDataView,
                  DropDataMetadataUniquePtr>::
    Read(common::mojom::DropDataMetadataDataView data,
         DropDataMetadataUniquePtr* out) {
  DCHECK(!out->get());
  out->reset(new common::DropDataMetadata());
  // (*out)->kind = data.kind();
  // return data.ReadData(&((*out)->mime_type)) &&
  //   data.ReadData(&((*out)->filename)) &&
  //   data.ReadData(&((*out)->file_system_url));
  return true;
}

// static
bool StructTraits<common::mojom::DropDataDataView,
                  DropDataUniquePtr>::
    Read(common::mojom::DropDataDataView data,
         DropDataUniquePtr* out) {
  DCHECK(!out->get());
  out->reset(new common::DropData());
  // (*out)->view_id = data.view_id();
  // (*out)->did_originate_from_renderer = data.did_originate_from_renderer();
  // (*out)->key_modifiers = data.key_modifiers();

  // return data.ReadData(&((*out)->url)) &&
  //   data.ReadUrlTitle(&((*out)->url_title)) &&
  //   data.ReadDownloadMetadata(&((*out)->download_metadata)) &&
  //   data.ReadFilenames(&((*out)->filenames)) &&
  //   data.ReadFileMimeTypes(&((*out)->file_mime_types)) &&
  //   data.ReadFilesystemId(&((*out)->filesystem_id)) &&
  //   data.ReadFileSystemFiles(&((*out)->file_system_files)) &&
  //   data.ReadText(&((*out)->text)) &&
  //   data.ReadHtml(&((*out)->html)) &&
  //   data.ReadHtmlBaseUrl(&((*out)->html_base_url)) &&
  //   data.ReadFileContents(&((*out)->file_contents)) &&
  //   data.ReadFileContentsSourceUrl(&((*out)->file_contents_source_url)) &&
  //   data.ReadFileContentsFilenameExtension(&((*out)->file_contents_filename_extension)) &&
  //   data.ReadFileContentsContentDisposition(&((*out)->file_contents_content_disposition)) &&
  //   data.ReadCustomData(&((*out)->custom_data));
  return true;
}

}  // namespace mojo
