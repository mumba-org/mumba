// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "BundleShims.h"

#include "CompositorStructsPrivate.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base//strings/string_piece.h"
#include "base/memory/ref_counted_memory.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/base/resource/resource_bundle.h"

//void _ResourceBundleInitInstance() {
  //if (!ui::ResourceBundle::HasSharedInstance()) {
  // ui::ResourceBundle::InitSharedInstanceWithPakPath(blink_resources); 
  //}
//}

// ResourceBundleRef _ResourceBundleGetInstance() {
//   DCHECK(ui::ResourceBundle::HasSharedInstance());
//   ui::ResourceBundle& instance = ui::ResourceBundle::GetSharedInstance();
//   return &instance;
// }

int _ResourceBundleAddDataPackFromPath(const char* relative_path, int scale_factor) {
  base::FilePath exe_path;
  base::GetCurrentDirectory(&exe_path);
  base::FilePath path = exe_path.Append(FILE_PATH_LITERAL(relative_path));
  //DLOG(INFO) << "\n\n ** _ResourceBundleAddDataPackFromPath: data pack: " << path.value();
  if (!base::PathExists(path)) {
    return 0;
  }
  if (!ui::ResourceBundle::HasSharedInstance()) {
    ui::ResourceBundle::InitSharedInstanceWithPakPath(path);
    return 1; 
  }
  ui::ResourceBundle& instance = ui::ResourceBundle::GetSharedInstance();
  instance.AddDataPackFromPath(path, static_cast<ui::ScaleFactor>(scale_factor));
  return 1;
}

ImageRef _ResourceBundleGetImageSkiaNamed(int resource_id) {
  DCHECK(ui::ResourceBundle::HasSharedInstance());
  ui::ResourceBundle& instance = ui::ResourceBundle::GetSharedInstance();
  gfx::ImageSkia* image = instance.GetImageSkiaNamed(resource_id);
  if (!image) {
    return nullptr;
  }
  const SkBitmap* bitmap = image->bitmap();
  DCHECK(bitmap);
  return new SkiaImage(SkImage::MakeFromBitmap(*bitmap));
}

int _ResourceBundleLoadDataResourceBytes(int resource_id, const uint8_t** bytes, size_t* bytes_size) {
  DCHECK(ui::ResourceBundle::HasSharedInstance());
  ui::ResourceBundle& instance = ui::ResourceBundle::GetSharedInstance();
  base::RefCountedMemory* data = instance.LoadDataResourceBytes(resource_id);
  if (!data) {
    return 0;
  }
  *bytes = data->front();
  *bytes_size = data->size(); 
  return 1;
}

int _ResourceBundleLoadDataResourceBytesForScale(int resource_id, int scale_factor, const uint8_t** bytes, size_t* bytes_size) {
  DCHECK(ui::ResourceBundle::HasSharedInstance());
  ui::ResourceBundle& instance = ui::ResourceBundle::GetSharedInstance();
  base::RefCountedMemory* data = instance.LoadDataResourceBytesForScale(resource_id, static_cast<ui::ScaleFactor>(scale_factor));
  if (!data) {
    return 0;
  }
  *bytes = data->front();
  *bytes_size = data->size();
  return 1;
}

// int _ResourceBundleGetLocalizedString(int message_id, uint16_t* const* bytes, size_t* bytes_size) {
//   DCHECK(ui::ResourceBundle::HasSharedInstance());
//   ui::ResourceBundle& instance = ui::ResourceBundle::GetSharedInstance();
//   base::string16 str = instance.GetLocalizedString(message_id);
//   if (str.empty()) {
//     return 0;
//   }
//   return 1;
// }

int _ResourceBundleGetRawDataResource(int message_id, const uint8_t** bytes, size_t* bytes_size) {
  DCHECK(ui::ResourceBundle::HasSharedInstance());
  ui::ResourceBundle& instance = ui::ResourceBundle::GetSharedInstance();
  base::StringPiece data = instance.GetRawDataResource(message_id);
  if (data.empty()) {
    return 0;
  }
  // no problem, as StringPiece is only a wrapper around owned/managed content
  // in this case mmaped memory
  *bytes = reinterpret_cast<const uint8_t *>(data.data());
  *bytes_size = data.size();
  return 1; 
}

int _ResourceBundleGetRawDataResourceForScale(int message_id, int scale_factor, const uint8_t** bytes, size_t* bytes_size) {
  DCHECK(ui::ResourceBundle::HasSharedInstance());
  ui::ResourceBundle& instance = ui::ResourceBundle::GetSharedInstance();
  base::StringPiece data = instance.GetRawDataResourceForScale(message_id, static_cast<ui::ScaleFactor>(scale_factor));
  if (data.empty()) {
    return 0;
  }
  // no problem, as StringPiece is only a wrapper around owned/managed content
  // in this case mmaped memory
  *bytes = reinterpret_cast<const uint8_t *>(data.data());
  *bytes_size = data.size();
  return 1;
}
