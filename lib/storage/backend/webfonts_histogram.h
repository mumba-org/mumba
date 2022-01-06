// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef STORAGE_STORAGE_BACKEND_BLOCKFILE_WEBFONTS_HISTOGRAM_H_
#define STORAGE_STORAGE_BACKEND_BLOCKFILE_WEBFONTS_HISTOGRAM_H_

#include <string>

namespace storage {

class StorageEntry;

// A collection of functions for histogram reporting about web fonts.
namespace web_fonts_histogram {

void RecordCacheMiss(const std::string& key);
void RecordEvictedEntry(const std::string& key);
void RecordCacheHit(StorageEntry* entry);
void RecordEviction(StorageEntry* entry);

}  // namespace web_fonts_histogram

}  // namespace storage

#endif  // STORAGE_STORAGE_BACKEND_BLOCKFILE_WEBFONTS_HISTOGRAM_H_
