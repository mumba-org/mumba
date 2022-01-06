// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/backend/webfonts_histogram.h"

#include "base/strings/string_piece.h"
#include "base/strings/stringprintf.h"
#include "storage/backend/storage_entry.h"
#include "storage/backend/histogram_macros.h"

namespace {

enum WebFontStorageCacheEventType {
  CACHE_EVENT_MISS,
  CACHE_EVENT_HIT,
  CACHE_EVENT_EVICTED_ENTRY,
  CACHE_EVENT_MAX
};

// Tests if the substring of str that begins at pos starts with substr. If so,
// returns true and advances pos by the length of substr.
bool Consume(const std::string& str, const base::StringPiece& substr,
             std::string::size_type* pos) {
  if (!str.compare(*pos, substr.length(), substr.data())) {
    *pos += substr.length();
    return true;
  }
  return false;
}

const char kRoboto[] = "roboto";
const char kOpenSans[] = "opensans";
const char kOthers[] = "others";

// Check if the given string is a URL for a font resource of Google Fonts.
// If so, returns a label for UMA histogram ("roboto", "opensans" or "others").
const char* HistogramLabel(const std::string& str) {
  std::string::size_type pos = 0;
  if (Consume(str, "http://", &pos) || Consume(str, "https://", &pos)) {
    if (Consume(str, "themes.googleusercontent.com/static/fonts/", &pos) ||
        Consume(str, "ssl.gstatic.com/fonts/", &pos) ||
        Consume(str, "fonts.gstatic.com/s/", &pos)) {
      if (Consume(str, kRoboto, &pos))
        return kRoboto;
      if (Consume(str, kOpenSans, &pos))
        return kOpenSans;
      return kOthers;
    }
  }
  return NULL;
}

std::string HistogramName(const char* prefix, const char* label) {
  return base::StringPrintf("WebFont.%s_%s", prefix, label);
}

void RecordCacheEvent(WebFontStorageCacheEventType type, const char* label) {
  CACHE_HISTOGRAM_ENUMERATION(HistogramName("StorageCacheHit", label),
                              type, CACHE_EVENT_MAX);
}

}  // namespace

namespace storage {
namespace web_fonts_histogram {

void RecordCacheMiss(const std::string& key) {
  const char* label = HistogramLabel(key);
  if (label)
    RecordCacheEvent(CACHE_EVENT_MISS, label);
}

void RecordEvictedEntry(const std::string& key) {
  const char* label = HistogramLabel(key);
  if (label)
    RecordCacheEvent(CACHE_EVENT_EVICTED_ENTRY, label);
}

void RecordCacheHit(StorageEntry* entry) {
  const char* label = HistogramLabel(entry->GetKey());
  if (!label)
    return;
  EntryStore* info = entry->entry()->Data();
  CACHE_HISTOGRAM_COUNTS_10000(HistogramName("StorageCache.ReuseCount.Hit", label),
                               info->reuse_count);
  CACHE_HISTOGRAM_AGE(HistogramName("StorageCache.EntryAge.Hit", label),
                      base::Time::FromInternalValue(info->creation_time));
  RecordCacheEvent(CACHE_EVENT_HIT, label);
}

void RecordEviction(StorageEntry* entry) {
  const char* label = HistogramLabel(entry->GetKey());
  if (!label)
    return;
  EntryStore* info = entry->entry()->Data();
  CACHE_HISTOGRAM_COUNTS_10000(
      HistogramName("StorageCache.ReuseCount.Evict", label),
      info->reuse_count);
  CACHE_HISTOGRAM_AGE(HistogramName("StorageCache.EntryAge.Evict", label),
                      base::Time::FromInternalValue(info->creation_time));
}

}  // namespace web_fonts_histogram
}  // namespace storage
