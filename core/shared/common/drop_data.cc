// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/drop_data.h"

#include "base/strings/utf_string_conversions.h"
#include "net/base/filename_util.h"
#include "net/base/mime_util.h"

namespace common {

DropDataMetadata::DropDataMetadata() {}

// static
DropDataMetadata DropDataMetadata::CreateForMimeType(
    const DropDataMetadataKind& kind,
    const base::string16& mime_type) {
  DropDataMetadata metadata;
  metadata.kind = kind;
  metadata.mime_type = mime_type;
  return metadata;
}

// static
DropDataMetadata DropDataMetadata::CreateForFilePath(
    const base::FilePath& filename) {
  DropDataMetadata metadata;
  metadata.kind = DropDataMetadataKind::FILENAME;
  metadata.filename = filename;
  return metadata;
}

// static
DropDataMetadata DropDataMetadata::CreateForFileSystemUrl(
    const GURL& file_system_url) {
  DropDataMetadata metadata;
  metadata.kind = DropDataMetadataKind::FILESYSTEMFILE;
  metadata.file_system_url = file_system_url;
  return metadata;
}

DropDataMetadata::DropDataMetadata(const DropDataMetadata& other) = default;

DropDataMetadata::~DropDataMetadata() {}

DropData::DropData()
    : did_originate_from_renderer(false),
     // referrer_policy(blink::kWebReferrerPolicyDefault),
      key_modifiers(0) {}

DropData::DropData(const DropData& other) = default;

DropData::~DropData() {}

base::Optional<base::FilePath> DropData::GetSafeFilenameForImageFileContents()
    const {
  base::FilePath file_name = net::GenerateFileName(
      file_contents_source_url, file_contents_content_disposition,
      std::string(),   // referrer_charset
      std::string(),   // suggested_name
      std::string(),   // mime_type
      std::string());  // default_name
  std::string mime_type;
  if (net::GetWellKnownMimeTypeFromExtension(file_contents_filename_extension,
                                             &mime_type) &&
      base::StartsWith(mime_type, "image/",
                       base::CompareCase::INSENSITIVE_ASCII)) {
    return file_name.ReplaceExtension(file_contents_filename_extension);
  }
  return base::nullopt;
}

// static
void DropData::FileSystemFileInfo::WriteFileSystemFilesToPickle(
    const std::vector<FileSystemFileInfo>& file_system_files,
    base::Pickle* pickle) {
  pickle->WriteUInt32(file_system_files.size());
  for (const auto& file_system_file : file_system_files) {
    pickle->WriteString(file_system_file.url.spec());
    pickle->WriteInt64(file_system_file.size);
    pickle->WriteString(file_system_file.filesystem_id);
  }
}

// static
bool DropData::FileSystemFileInfo::ReadFileSystemFilesFromPickle(
    const base::Pickle& pickle,
    std::vector<FileSystemFileInfo>* file_system_files) {
  base::PickleIterator iter(pickle);

  uint32_t num_files = 0;
  if (!iter.ReadUInt32(&num_files))
    return false;
  file_system_files->resize(num_files);

  for (uint32_t i = 0; i < num_files; ++i) {
    std::string url_string;
    int64_t size = 0;
    std::string filesystem_id;
    if (!iter.ReadString(&url_string) || !iter.ReadInt64(&size) ||
        !iter.ReadString(&filesystem_id)) {
      return false;
    }

    GURL url(url_string);
    if (!url.is_valid()) {
      return false;
    }

    (*file_system_files)[i].url = url;
    (*file_system_files)[i].size = size;
    (*file_system_files)[i].filesystem_id = filesystem_id;
  }
  return true;
}

}  // namespace content
