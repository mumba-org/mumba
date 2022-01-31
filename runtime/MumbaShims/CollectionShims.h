// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_STORE_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_STORE_SHIMS_H_

#include "Globals.h"

typedef void* CollectionRef;
typedef void* CollectionWatcherRef;
typedef void* EngineInstanceRef;

// AddEntry(CollectionEntry entry) => (CollectionStatusCode reply);
// AddEntryByAddress(CollectionEntryDescriptor descriptor) => (CollectionStatusCode reply);
// RemoveEntry(string address) => (CollectionStatusCode reply);
// RemoveEntryByUUID(string uuid) => (CollectionStatusCode reply);
// LookupEntry(string address) => (CollectionStatusCode code, CollectionEntry? entry);
// LookupEntryByName(string name) => (CollectionStatusCode code, CollectionEntry? entry);
// LookupEntryByUUID(string uuid) => (CollectionStatusCode code, CollectionEntry? entry);
// HaveEntry(string address) => (bool have);
// HaveEntryByName(string name) => (bool have);
// HaveEntryByUUID(string uuid) => (bool have);
// ListEntries() => (array<CollectionEntry> entries);
// GetEntryCount() => (uint32 count);

/*
  string uuid;
  string name;
  string description;
  string version;
  string license;
  string publisher;
  string publisher_url;  
  string publisher_public_key;
  string logo_path;
  uint64 size;
  string repo_uuid;
  string repo_public_key;
  CollectionInstallState install_state;
  CollectionAvailabilityState availability_state;
  uint64 install_counter;
  uint32 rating;
  string app_public_key;
  array<string> supported_platforms;
  array<string> supported_languages;
 */


EXPORT CollectionRef _CollectionCreateFromEngine(EngineInstanceRef handle);
EXPORT void _CollectionDestroy(CollectionRef handle);
EXPORT void _CollectionAddEntry(CollectionRef handle, 
  const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**, 
  void* state, 
  void(*callback)(void*, int));
EXPORT void _CollectionAddEntryByAddress(CollectionRef handle, 
  const char*,
  void* state, 
  void(*callback)(void*, int));
EXPORT void _CollectionRemoveEntry(CollectionRef handle, const char* address, void* state, void(*callback)(void*, int));
EXPORT void _CollectionRemoveEntryByUUID(CollectionRef handle, const char* uuid, void* state, void(*callback)(void*, int));
EXPORT void _CollectionLookupEntry(CollectionRef handle, const char* address, void* state, void(*callback)(
  void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**));
EXPORT void _CollectionLookupEntryByName(CollectionRef handle, const char* name, void* state, void(*callback)(
  void*, int,
  const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**));
EXPORT void _CollectionLookupEntryByUUID(CollectionRef handle, const char* uuid, void* state, void(*callback)(
  void*, int, 
  const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**));
EXPORT void _CollectionHaveEntry(CollectionRef handle, const char* address, void* state, void(*callback)(void*, int));
EXPORT void _CollectionHaveEntryByName(CollectionRef handle, const char* name, void* state, void(*callback)(void*, int));
EXPORT void _CollectionHaveEntryByUUID(CollectionRef handle, const char* uuid, void* state, void(*callback)(void*, int));
EXPORT void _CollectionListEntries(CollectionRef handle, void* state, void(*callback)(
  void*, int,
  const char**, const char**, const char**, const char**, 
  const char**, const char**, const char**, const char**, 
  const char**, uint64_t*, const char**, const char**,
  int*, int*, uint64_t*, uint32_t*, const char**, 
  int*, const char***, int*, const char***));
EXPORT void _CollectionGetEntryCount(CollectionRef handle, void* state, void(*callback)(void*, int));
EXPORT void _CollectionAddWatcher(
  CollectionRef handle, 
  void* state,
  void* watcher_state, 
  void(*OnEntryAdded)(void*, const char*, const char*, const char*, const char*, 
                      const char*, const char*, const char*, const char*, 
                      const char*, uint64_t, const char*, const char*,
                      int, int, uint64_t, uint32_t, const char*, 
                      int, const char**, int, const char**),
  void(*OnEntryRemoved)(void*, const char*, const char*, const char*, const char*, 
                        const char*, const char*, const char*, const char*, 
                        const char*, uint64_t, const char*, const char*,
                        int, int, uint64_t, uint32_t, const char*, 
                        int, const char**, int, const char**));
EXPORT void _CollectionRemoveWatcher(CollectionRef handle, int32_t watcher);
EXPORT void _CollectionWatcherDestroy(void* handle);

#endif
