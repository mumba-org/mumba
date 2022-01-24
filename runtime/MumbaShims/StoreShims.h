// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_STORE_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_STORE_SHIMS_H_

#include "Globals.h"

typedef void* AppStoreRef;
typedef void* AppStoreWatcherRef;
typedef void* EngineInstanceRef;

typedef struct {
 int (*GetAppCount)(void* state);
} AppStoreCallbacks;

// AddEntry(AppStoreEntry entry) => (AppStoreStatusCode reply);
// AddEntryByAddress(AppStoreEntryDescriptor descriptor) => (AppStoreStatusCode reply);
// RemoveEntry(string address) => (AppStoreStatusCode reply);
// RemoveEntryByUUID(string uuid) => (AppStoreStatusCode reply);
// LookupEntry(string address) => (AppStoreStatusCode code, AppStoreEntry? entry);
// LookupEntryByName(string name) => (AppStoreStatusCode code, AppStoreEntry? entry);
// LookupEntryByUUID(string uuid) => (AppStoreStatusCode code, AppStoreEntry? entry);
// HaveEntry(string address) => (bool have);
// HaveEntryByName(string name) => (bool have);
// HaveEntryByUUID(string uuid) => (bool have);
// ListEntries() => (array<AppStoreEntry> entries);
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
  AppStoreInstallState install_state;
  AppStoreAvailabilityState availability_state;
  uint64 install_counter;
  uint32 rating;
  string app_public_key;
  array<string> supported_platforms;
  array<string> supported_languages;
 */


EXPORT AppStoreRef _AppStoreCreateFromEngine(EngineInstanceRef handle, void* state, AppStoreCallbacks callbacks);
EXPORT void _AppStoreDestroy(AppStoreRef handle);
EXPORT void _AppStoreAddEntry(AppStoreRef handle, 
  const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**, 
  void(*callback)(void*, int));
EXPORT void _AppStoreAddEntryByAddress(AppStoreRef handle, 
  const char*,
  void(*callback)(void*, int));
EXPORT void _AppStoreRemoveEntry(AppStoreRef handle, const char* address, void(*callback)(void*, int));
EXPORT void _AppStoreRemoveEntryByUUID(AppStoreRef handle, const char* uuid, void(*callback)(void*, int));
EXPORT void _AppStoreLookupEntry(AppStoreRef handle, const char* address, void(*callback)(
  void*, int, const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**));
EXPORT void _AppStoreLookupEntryByName(AppStoreRef handle, const char* name, void(*callback)(
  void*, int,
  const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**));
EXPORT void _AppStoreLookupEntryByUUID(AppStoreRef handle, const char* uuid, void(*callback)(
  void*, int, 
  const char*, const char*, const char*, const char*, 
  const char*, const char*, const char*, const char*, 
  const char*, uint64_t, const char*, const char*,
  int, int, uint64_t, uint32_t, const char*, 
  int, const char**, int, const char**));
EXPORT void _AppStoreHaveEntry(AppStoreRef handle, const char* address, void(*callback)(void*, int));
EXPORT void _AppStoreHaveEntryByName(AppStoreRef handle, const char* name, void(*callback)(void*, int));
EXPORT void _AppStoreHaveEntryByUUID(AppStoreRef handle, const char* uuid, void(*callback)(void*, int));
EXPORT void _AppStoreListEntries(AppStoreRef handle, void(*callback)(
  void*, int,
  const char**, const char**, const char**, const char**, 
  const char**, const char**, const char**, const char**, 
  const char**, uint64_t*, const char**, const char**,
  int*, int*, uint64_t*, uint32_t*, const char**, 
  int, const char***, int, const char***));
EXPORT void _AppStoreGetEntryCount(AppStoreRef handle, void(*callback)(void*, int));
EXPORT void _AppStoreAddWatcher(
  AppStoreRef handle, 
  void* state,
  void* watcher_state, 
  void(*cb)(void*, int, void*, void*),
  void(*OnEntryAdded)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*),
  void(*OnEntryRemoved)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*));
EXPORT void _AppStoreRemoveWatcher(AppStoreRef handle, int32_t watcher);

#endif
