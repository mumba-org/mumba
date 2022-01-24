// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_REPO_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_REPO_SHIMS_H_

#include "Globals.h"

typedef void* RepoRegistryRef;
typedef void* RepoWatcherRef;
typedef void* EngineInstanceRef;

typedef struct {
 int (*GetRepoCount)(void* state);
} RepoRegistryCallbacks;

EXPORT RepoRegistryRef _RepoRegistryCreateFromEngine(EngineInstanceRef handle, void* state, RepoRegistryCallbacks callbacks);
EXPORT void _RepoRegistryDestroy(RepoRegistryRef handle);   
EXPORT void _RepoRegistryAddRepo(RepoRegistryRef handle, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*, void(*callback)(void*, int));
EXPORT void _RepoRegistryAddRepoByAddress(RepoRegistryRef handle, const char*, void(*callback)(void*, int));
EXPORT void _RepoRegistryRemoveRepo(RepoRegistryRef handle, const char* address, void(*callback)(void*, int));
EXPORT void _RepoRegistryRemoveRepoByUUID(RepoRegistryRef handle, const char* uuid, void(*callback)(void*, int));
EXPORT void _RepoRegistryLookupRepo(RepoRegistryRef handle, const char* address, void(*callback)(void*, int, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*));
EXPORT void _RepoRegistryLookupRepoByName(RepoRegistryRef handle, const char* name, void(*callback)(void*, int, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*));
EXPORT void _RepoRegistryLookupRepoByUUID(RepoRegistryRef handle, const char* uuid, void(*callback)(void*, int, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*));
EXPORT void _RepoRegistryHaveRepo(RepoRegistryRef handle, const char* address, void(*callback)(void*, int));
EXPORT void _RepoRegistryHaveRepoByName(RepoRegistryRef handle, const char* name, void(*callback)(void*, int));
EXPORT void _RepoRegistryHaveRepoByUUID(RepoRegistryRef handle, const char* uuid, void(*callback)(void*, int));
EXPORT void _RepoRegistryListRepos(RepoRegistryRef handle, void(*callback)(void*, int, const char**, int*, const char**, const char**, int*, const char**, const char**, int*, const char**, const char**));
EXPORT void _RepoRegistryGetRepoCount(RepoRegistryRef handle, void(*callback)(void*, int));
EXPORT void _RepoRegistryAddWatcher(RepoRegistryRef handle, 
  void* state,
  void* watcher_state, 
  void(*cb)(void*, int, void*, void*),
  void(*OnEntryAdded)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*),
  void(*OnEntryRemoved)(void*, const char*, int, const char*, const char*, int, const char*, const char*, int, const char*, const char*));
EXPORT void _RepoRegistryRemoveWatcher(RepoRegistryRef handle, int32_t watcher);

#endif